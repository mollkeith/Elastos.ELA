// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// GUARD CALLS MUST BE EFFECTIVE, not merely present.
//
// THE EVIDENCE GAP THIS CLOSES. wiring_callsites_test.go asserts each guard is still CALLED
// from its production function, and says so about its own limit: "a structural assertion
// cannot tell an effective call from an ineffective one (a call whose error is discarded,
// or whose arguments are constants)". A mutation battery then exploited exactly that. It
// never deletes a call — it leaves the call in place and neuters the condition that
// consumes its error:
//
//	if err := checkNFTDestroyGenesisBinding(...); err != nil { return ... }
//	if err := checkNFTDestroyGenesisBinding(...); false && (err != nil) { return ... }
//
// The call-site inventory sees no difference. The guard is dead.
//
// This test adds the missing half of that contract for the guard calls whose BEHAVIOURAL
// test cannot be written cheaply. It asserts that the error returned by the named guard is
// consumed by an UNWEAKENED `err != nil` test whose body returns:
//
//   - the enclosing statement must be an `if`;
//   - its condition must be exactly `<ident> != nil` — not a conjunction, not a
//     disjunction, not an inversion, not a literal;
//   - the identifier tested must be the one the call assigns;
//   - the body must contain a `return`.
//
// It is still a structural layer and still not a substitute for a behavioural test. It is
// the cheapest assertion that distinguishes an armed guard from a disarmed one, and it is
// the only layer that can cover F-052 at all: its behavioural precondition
// (Producer.detailedDPoSV2Votes, an unexported dpos/state field read by CanNFTDestroy)
// cannot be established from the core/transaction package, and dpos/state cannot import
// core/transaction without an import cycle.
package unit

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// consumedCall is one production edge where a guard`s error must actually gate a return.
type consumedCall struct {
	finding string
	file    string
	fn      string
	callee  string
	why     string
}

var errConsumingCallSites = []consumedCall{
	{
		finding: "F-052",
		file:    "core/transaction/nftdestroytransaction.go", fn: "SpecialContextCheck",
		callee: "checkNFTDestroyGenesisBinding",
		why: "the ONLY layer covering F-052: its behavioural precondition cannot be " +
			"established from this package (see the file comment)",
	},
	{
		finding: "F-118/F-028 family",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockSanity",
		callee: "CheckSameBlockConflicts",
		why:    "the whole same-block conflict family is reached through this one call",
	},
	{
		finding: "F-089",
		file:    "blockchain/blockvalidator.go", fn: "checkTxsContext",
		callee: "checkCoinbaseBIP30",
		why:    "a discarded error re-opens coinbase remint (BIP30)",
	},
	{
		finding: "F-013",
		file:    "blockchain/blockvalidator.go", fn: "checkCoinbaseTransactionContext",
		callee: "checkCoinbaseFrozenOutputs",
		why:    "a discarded error lets the coinbase pay a quarantined address",
	},
	{
		finding: "FV-19",
		file:    "blockchain/blockvalidator.go", fn: "checkCoinbaseTransactionContext",
		callee: "checkCoinbaseLockTimePin",
		why:    "a discarded error un-pins the coinbase LockTime maturity window",
	},
}

// callsCallee reports whether the expression tree rooted at n contains a call to callee.
func callsCallee(n ast.Node, callee string) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == callee {
				found = true
			}
		case *ast.SelectorExpr:
			if fun.Sel.Name == callee || strings.HasSuffix(callee, "."+fun.Sel.Name) {
				found = true
			}
		}
		return !found
	})
	return found
}

// bodyReturns reports whether a block contains a return statement.
func bodyReturns(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(x ast.Node) bool {
		if _, ok := x.(*ast.ReturnStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// errIdent returns the identifier name of an unweakened `<ident> != nil` condition, or "".
func errIdent(cond ast.Expr) string {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	nilIdent, ok := bin.Y.(*ast.Ident)
	if !ok || nilIdent.Name != "nil" {
		return ""
	}
	lhs, ok := bin.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return lhs.Name
}

// assignedNames returns the names an if-statement`s init assignment binds.
func assignedNames(init ast.Stmt) []string {
	as, ok := init.(*ast.AssignStmt)
	if !ok {
		return nil
	}
	var names []string
	for _, l := range as.Lhs {
		if id, ok := l.(*ast.Ident); ok {
			names = append(names, id.Name)
		}
	}
	return names
}

func TestWiringGuardErrorsAreActuallyConsumed(t *testing.T) {
	root := repoRoot(t)

	for _, cc := range errConsumingCallSites {
		cc := cc
		t.Run(strings.ReplaceAll(cc.finding, "/", "_")+"__"+cc.fn+"__"+cc.callee, func(t *testing.T) {
			fd, _ := funcBody(t, root, callSite{file: cc.file, fn: cc.fn, callee: cc.callee})

			var guard *ast.IfStmt
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || guard != nil {
					return true
				}
				if ifs.Init != nil && callsCallee(ifs.Init, cc.callee) {
					guard = ifs
					return false
				}
				if callsCallee(ifs.Cond, cc.callee) {
					guard = ifs
					return false
				}
				return true
			})

			if guard == nil {
				t.Fatalf("GUARD NOT CONSUMED [%s]: %s.%s contains no `if` statement that "+
					"evaluates %s. The call may still be present, but nothing tests its "+
					"result.\n%s", cc.finding, cc.file, cc.fn, cc.callee, cc.why)
			}

			name := errIdent(guard.Cond)
			if name == "" {
				t.Fatalf("GUARD DISARMED [%s]: %s.%s calls %s but its error is gated by a "+
					"condition that is not a plain `err != nil` (a conjunction, a "+
					"disjunction, an inversion or a literal will silently disable it).\n%s",
					cc.finding, cc.file, cc.fn, cc.callee, cc.why)
			}

			if bound := assignedNames(guard.Init); guard.Init != nil {
				ok := false
				for _, b := range bound {
					if b == name {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("GUARD DISARMED [%s]: %s.%s tests %q, which is not what the "+
						"%s call assigns (%v).\n%s", cc.finding, cc.file, cc.fn, name,
						cc.callee, bound, cc.why)
				}
			}

			if !bodyReturns(guard.Body) {
				t.Fatalf("GUARD DISARMED [%s]: %s.%s tests the %s error but does not return "+
					"on it, so the rejection never reaches the caller.\n%s",
					cc.finding, cc.file, cc.fn, cc.callee, cc.why)
			}
		})
	}
}
