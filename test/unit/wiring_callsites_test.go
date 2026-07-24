// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — STRUCTURAL call-site inventory.
//
// This is the BACKSTOP layer, not the primary proof. The behavioural wiring tests
// (blockchain/wiring_*.go, dpos/state/f096_capture_wiring_test.go,
// core/checkpoint/f122_atomic_wiring_test.go, core/transaction/f015_siblings_test.go)
// drive the real production entry points and are what actually prove each guard is armed.
// This test adds a second, cheap, complete layer over the SAME inventory: it parses the
// production sources and asserts that each named guard is still CALLED FROM the named
// production function.
//
// Why it earns its place:
//   - it covers the links a behavioural test cannot reach cheaply — notably the
//     CheckBlockContext -> checkTxsContext link (severing it disarms F-089 and every other
//     tx-context check without touching the F-089 call site itself), and F-052, whose
//     behavioural precondition (Producer.detailedDPoSV2Votes, an unexported field read by
//     CanNFTDestroy) cannot be established from the core/transaction package;
//   - it fails on a DELETED CALL, which is the exact mutation class the review found;
//   - it is one place a reviewer can read the whole armed-guard inventory.
//
// It is deliberately NOT a substitute for the behavioural tests: a structural assertion
// cannot tell an effective call from an ineffective one (a call whose error is discarded,
// or whose arguments are constants). Those cases are covered behaviourally and, where the
// argument identity is load-bearing, asserted here too.
package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// callSite is one required production edge: within `file`, function `fn` must contain a
// call to `callee`. `mustArgs` are argument expressions (rendered source) that must appear
// in that call — used where a constant would make the call inert.
type callSite struct {
	finding  string
	file     string
	fn       string
	callee   string
	mustArgs []string
	why      string
}

// requiredCallSites is the armed-guard inventory. Every entry corresponds to a mutation
// the G2 review ran (or to the parent link that would disarm one).
var requiredCallSites = []callSite{
	{
		finding: "F-016/017/028/030/047/051/066/067/068/071/072/078/083/100/118",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockSanity",
		callee:   "CheckSameBlockConflicts",
		mustArgs: []string{"block", "b.chainParams.StrictMoneyRangeHeight"},
		why:      "one call site protects the whole same-block conflict family (~15 findings)",
	},
	{
		finding: "F-041/F-090",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockSanity",
		callee: "auxPowMalleationActive",
		why:    "canonical-AuxPow gate; without it a malleated encoding seeds a divergent committee",
	},
	{
		finding: "F-041/F-090",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockSanity",
		callee: "IsCanonical",
		why:    "the canonical predicate itself must be consulted inside the gate",
	},
	{
		finding: "F-089 (INFLATION CLASS)",
		file:    "blockchain/blockvalidator.go", fn: "checkTxsContext",
		callee:   "checkCoinbaseBIP30",
		mustArgs: []string{"block.Height", "b.chainParams.StrictMoneyRangeHeight", "b.db.IsTxHashDuplicate"},
		why:      "BIP30 coinbase re-mint; the coinbase's own guard is dead on connect",
	},
	{
		finding: "F-089 parent link",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockContext",
		callee: "checkTxsContext",
		why:    "severing this link disarms F-089 and every per-transaction context check at once",
	},
	// F-032's CheckRecordSponsorBinding call site was REMOVED, not weakened — see
	// forbiddenCallSites below, which asserts it stays removed. NX-01 proved it keyed block
	// validity on lastBlock.Confirm.Proposal.Sponsor, a per-node stored value nothing
	// commits to, that the miner and the validator derived by different rules, and that
	// honest nodes legitimately disagree about after a DPoS view change.
	{
		finding: "F-013",
		file:    "blockchain/blockvalidator.go", fn: "checkCoinbaseTransactionContext",
		callee: "checkCoinbaseFrozenOutputs",
		why:    "the coinbase path otherwise bypasses checkFrozenAddresses entirely",
	},
	{
		finding: "F-049/F-091",
		file:    "blockchain/txvalidator.go", fn: "checkTransactionSignature",
		callee:   "RunPrograms",
		mustArgs: []string{"blockHeight", "strictMoneyHeight"},
		why:      "the default-deny gate is inert unless the real block height is threaded in",
	},
	{
		finding: "F-049/F-091 (second caller)",
		file:    "core/transaction/transactionchecker.go", fn: "checkTransactionSignature",
		callee:   "blockchain.RunPrograms",
		mustArgs: []string{"blockHeight", "strictMoneyHeight"},
		why:      "both callers had to be mutated together to disarm the gate",
	},
	{
		finding: "F-052",
		file:    "core/transaction/nftdestroytransaction.go", fn: "SpecialContextCheck",
		callee:   "checkNFTDestroyGenesisBinding",
		mustArgs: []string{"t.parameters.BlockHeight", "t.parameters.Config.StrictMoneyRangeHeight"},
		why:      "binds each destroyed NFT to the sidechain it was created on",
	},
	{
		finding: "F-093/F-094/F-106 site 1+2",
		file:    "blockchain/blockchain.go", fn: "replayCheckpointBlock",
		callee: "UndoPendingSpecialTx",
		why:    "a replay that aborts must not leave the emergency ForceChange applied",
	},
	{
		finding: "F-093/F-094/F-106 site 1+2",
		file:    "blockchain/blockchain.go", fn: "replayCheckpointBlock",
		callee: "CommitPendingSpecialTx",
		why:    "a replayed main-chain block commits its special-tx effect as it historically was",
	},
	{
		finding: "F-093/F-094/F-106 site 3",
		file:    "blockchain/blockchain.go", fn: "ProcessIllegalBlock",
		callee: "CommitPendingSpecialTx",
		why:    "the gossip path is not bracketed by a block connect",
	},
	{
		finding: "F-093/F-094/F-106 site 4",
		file:    "blockchain/blockchain.go", fn: "ProcessInactiveArbiter",
		callee: "CommitPendingSpecialTx",
		why:    "the gossip path is not bracketed by a block connect",
	},
	{
		// G1 (17f1c09) moved the bracket body out of connectBlock into
		// connectBlockBracketed so events.Notify(ETBlockConnected) runs OUTSIDE
		// specialTxMtx. The bracket is unchanged; only the function that holds it moved,
		// which is why the parent-link row below is now part of the inventory.
		finding: "F-093/F-094/F-106 site 5",
		file:    "blockchain/blockchain.go", fn: "connectBlockBracketed",
		callee: "UndoPendingSpecialTx",
		why:    "a block that fails to connect must not leave the node on a rejected arbiter set",
	},
	{
		finding: "F-093/F-094/F-106 site 6",
		file:    "blockchain/blockchain.go", fn: "connectBlockBracketed",
		callee: "CommitPendingSpecialTx",
		why:    "a block that connects commits its special-tx effect",
	},
	{
		finding: "#4 lock bracket",
		file:    "blockchain/blockchain.go", fn: "connectBlockBracketed",
		callee: "LockSpecialTx",
		why:    "the whole bracket must be serialized against the gossip brackets",
	},
	{
		finding: "F-093/F-094/F-106 site 5+6 parent link",
		file:    "blockchain/blockchain.go", fn: "connectBlock",
		callee: "connectBlockBracketed",
		why: "connectBlock is the production entry point; severing this one call disarms the " +
			"whole bracket, and every connect-time check, without touching a bracket call site",
	},
	{
		finding: "F-122",
		file:    "core/checkpoint/channels.go", fn: "saveCheckpoint",
		callee: "writeFileAtomic",
		why:    "an in-place checkpoint write leaves a short file that is still promoted to default",
	},
	{
		finding: "Residue #2",
		file:    "blockchain/forcedrollback.go", fn: "ForceRollback",
		callee:   "PurgeForcedRollbackResidue",
		mustArgs: []string{"b.db.GetFFLDB()", "target"},
		why: "without the orphan sweep a rolled-back node still SERVES the exploit block by " +
			"hash over RPC and P2P (PROVEN live)",
	},
}

// funcBody finds the (possibly method) declaration named fn in file.
func funcBody(t *testing.T, root string, cs callSite) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, cs.file), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("[%s] cannot parse %s: %v", cs.finding, cs.file, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Name.Name == cs.fn && fd.Body != nil {
			return fd, fset
		}
	}
	t.Fatalf("[%s] %s: function %s not found — the wiring inventory is stale, or the "+
		"production function was renamed away from its guard", cs.finding, cs.file, cs.fn)
	return nil, nil
}

// renderCall returns the source text of a call expression's callee and arguments.
func renderCall(fset *token.FileSet, src []byte, n ast.Node) string {
	start := fset.Position(n.Pos()).Offset
	end := fset.Position(n.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	return string(src[start:end])
}

// TestWiringRequiredCallSitesArePresent asserts every guard in the inventory is still
// called from the production function that must call it.
//
// MUTATION PROOF: delete any one of these calls and this test names the finding it
// disarmed. It is the complete-coverage layer over the behavioural tests.
func TestWiringRequiredCallSitesArePresent(t *testing.T) {
	root := repoRoot(t)

	for _, cs := range requiredCallSites {
		cs := cs
		t.Run(strings.ReplaceAll(cs.finding, "/", "_")+"__"+cs.fn+"__"+cs.callee, func(t *testing.T) {
			fd, fset := funcBody(t, root, cs)

			var found *ast.CallExpr
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					name = fun.Sel.Name
					if pkg, ok := fun.X.(*ast.Ident); ok {
						if pkg.Name+"."+fun.Sel.Name == cs.callee {
							name = cs.callee
						}
					}
				}
				if name == cs.callee || strings.HasSuffix(cs.callee, "."+name) {
					found = call
					return false
				}
				return true
			})

			if found == nil {
				t.Fatalf("WIRING SEVERED [%s]: %s.%s no longer calls %s.\n%s",
					cs.finding, cs.file, cs.fn, cs.callee, cs.why)
			}

			if len(cs.mustArgs) == 0 {
				return
			}
			var rendered []string
			for _, a := range found.Args {
				rendered = append(rendered, renderArg(fset, root, cs.file, a))
			}
			joined := strings.Join(rendered, " | ")
			for _, want := range cs.mustArgs {
				if !strings.Contains(joined, want) {
					t.Fatalf("WIRING INERT [%s]: %s.%s calls %s but no longer passes %q "+
						"(args: %s).\n%s — a call that passes a constant here is wired but inert",
						cs.finding, cs.file, cs.fn, cs.callee, want, joined, cs.why)
				}
			}
		})
	}
}

// renderArg renders one argument expression back to source text.
func renderArg(fset *token.FileSet, root, rel string, a ast.Expr) string {
	src, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return ""
	}
	return renderCall(fset, src, a)
}

// -----------------------------------------------------------------------------
// NX-01 / NX-05 — the NEGATIVE inventory.
//
// Some guards are wrong to have. F-032's block-validity binding was one: withdrawing it is
// the Tier 0 release-shape decision, and the failure mode is that it comes BACK — inline,
// under a new name, or as a restored interface method — because "bind the sponsor" reads
// like a tightening rather than the chain split it is. The behavioural proof lives in
// blockchain/nx01_recordsponsor_nofork_test.go; this is the cheap structural backstop over
// the same property, and it is the layer that survives someone deleting that test file.
// -----------------------------------------------------------------------------

// forbiddenCallSite is a production edge that must NOT exist.
type forbiddenCallSite struct {
	finding string
	file    string
	fn      string // "" means: anywhere in the file, including as a declaration
	callee  string
	why     string
}

var forbiddenCallSites = []forbiddenCallSite{
	{
		finding: "NX-01",
		file:    "blockchain/blockvalidator.go", fn: "CheckBlockContext",
		callee: "CheckRecordSponsorBinding",
		why: "block validity must not be a function of lastBlock.Confirm.Proposal.Sponsor: " +
			"no hash or signature commits to it, pow/service.go reads it raw while the " +
			"validator resolved it through the operator sponsors file, and two honest nodes " +
			"hold different values after a view change — this is a permanent chain split at " +
			"RevisedDPoSRewardHeight, not a tightening",
	},
	{
		finding: "NX-01",
		file:    "dpos/state/arbitrators.go", fn: "",
		callee: "CheckRecordSponsorBinding",
		why: "the guard is DELETED, not merely unwired — a method with no production caller " +
			"reads as armed while enforcing nothing",
	},
}

// TestWiringForbiddenCallSitesAreAbsent fails if a withdrawn guard is reintroduced.
func TestWiringForbiddenCallSitesAreAbsent(t *testing.T) {
	root := repoRoot(t)

	for _, fs := range forbiddenCallSites {
		fs := fs
		name := fs.finding + "__" + strings.ReplaceAll(fs.file, "/", "_")
		if fs.fn != "" {
			name += "__" + fs.fn
		}
		t.Run(name+"__no_"+fs.callee, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(root, fs.file), nil, parser.AllErrors)
			if err != nil {
				t.Fatalf("[%s] cannot parse %s: %v", fs.finding, fs.file, err)
			}

			var scope ast.Node = f
			if fs.fn != "" {
				var fd *ast.FuncDecl
				for _, d := range f.Decls {
					if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == fs.fn && x.Body != nil {
						fd = x
						break
					}
				}
				if fd == nil {
					t.Fatalf("[%s] %s: function %s not found — the negative inventory is stale",
						fs.finding, fs.file, fs.fn)
				}
				scope = fd.Body
			}

			ast.Inspect(scope, func(n ast.Node) bool {
				var name string
				switch x := n.(type) {
				case *ast.Ident:
					name = x.Name
				case *ast.SelectorExpr:
					name = x.Sel.Name
				default:
					return true
				}
				if name == fs.callee {
					pos := fset.Position(n.Pos())
					t.Fatalf("WITHDRAWN GUARD REINTRODUCED [%s]: %s references %s at %s.\n%s",
						fs.finding, fs.file, fs.callee, pos, fs.why)
				}
				return true
			})
		})
	}
}

// sponsorsOverrideAllowedFuncs are the ONLY functions permitted to read the operator
// sponsors file's override map. Both are upstream (d8488bf) and neither decides whether a
// block is accepted: Arbiters.ProcessBlock feeds countArbitratorsInactivity*, and
// accumulateReward reads it only on the pre-RecordSponsorStartHeight branch, i.e. for
// retained history. NewArbitrators merely installs the loaded map.
var sponsorsOverrideAllowedFuncs = map[string]string{
	"ProcessBlock":     "upstream: selects the sponsor handed to countArbitratorsInactivity*",
	"accumulateReward": "upstream: pre-RecordSponsorStartHeight reward attribution only",
	"NewArbitrators":   "installs the loaded map; does not consult it",
}

// TestNX05SponsorsOverrideIsNotABlockValidityInput pins the NX-05 half of the decision: an
// operator-local, unversioned, unauthenticated file must never decide whether a BLOCK is
// valid. Above RecordSponsorStartHeight upstream deliberately moved sponsor attribution off
// the node-local confirm and into the block; the override map is a legacy correction for
// the era before that and must not leak forward into acceptance.
func TestNX05SponsorsOverrideIsNotABlockValidityInput(t *testing.T) {
	root := repoRoot(t)
	const rel = "dpos/state/arbitrators.go"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", rel, err)
	}

	seen := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || id.Name != "BlockConfirmProposalSponsors" {
				return true
			}
			if _, allowed := sponsorsOverrideAllowedFuncs[fd.Name.Name]; !allowed {
				t.Fatalf("NX-05 REGRESSION: %s reads BlockConfirmProposalSponsors at %s. The "+
					"operator sponsors file is unversioned, unauthenticated and node-local; "+
					"the only functions allowed to consult it are %v, none of which decides "+
					"block acceptance.", fd.Name.Name, fset.Position(id.Pos()),
					sortedKeys(sponsorsOverrideAllowedFuncs))
			}
			seen[fd.Name.Name] = true
			return true
		})
	}

	// The inventory must not rot in the other direction either: if a listed site
	// disappears, someone changed the override's reach and this test must be re-reasoned.
	for fn := range sponsorsOverrideAllowedFuncs {
		if fn == "NewArbitrators" {
			continue // installs the map by field name in a composite literal
		}
		if !seen[fn] {
			t.Fatalf("NX-05: %s no longer reads BlockConfirmProposalSponsors — the override's "+
				"reach changed; re-verify which sites remain before trusting this test", fn)
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
