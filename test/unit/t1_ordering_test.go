// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- STRUCTURAL guard on the forced-rollback step ORDER.
//
// The behavioural tests in t1_rollback_atomic_test.go prove the ordering matters.
// This file pins the ordering itself, because the regression is a two-line move
// that reads as a harmless tidy-up in review and that no compiler, linter or type
// signature can catch. A block's header-index row is the row b.Nodes is rebuilt
// from at startup, so deleting it before the block's rollback transaction has
// committed makes that block permanently un-rollbackable -- and, because main.go
// exits on the error, every operator restart eats one more row until the node boots
// silently at the target with the discarded blocks (mainnet: 2,260,451 among them)
// still main-chain indexed and still served by hash.
package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// t1OrderedCalls is one function whose calls must appear in a given source order.
type t1OrderedCalls struct {
	file  string
	fn    string
	first string // the destructive, committing step
	last  string // the step that must not precede it
	why   string
}

var t1RequiredOrder = []t1OrderedCalls{
	{
		file: "blockchain/forcedrollback.go", fn: "rollbackOneBlock",
		first: "RollbackBlock", last: "dbRemoveBlockNodeKey",
		why: "the rollback transaction (which also reverts the UTXO/state processors " +
			"and deletes the main-chain index entry) must commit BEFORE the header-index " +
			"row is removed, so an interruption leaves the block still in b.Nodes and the " +
			"rewind resumes",
	},
	{
		file: "blockchain/forcedrollback.go", fn: "rollbackOneBlock",
		first: "DBRemoveBlockFromStore", last: "dbRemoveBlockNodeKey",
		why: "the raw by-hash purge must also precede the header-row removal, for the " +
			"same reason",
	},
	{
		file: "cmd/rollback/rollback.go", fn: "rollbackAction",
		first: "RollbackBlock", last: "removeBlockNode",
		why: "`ela-cli rollback` is the operator remedy the forced-rollback error message " +
			"points at, and it carried the identical header-row-first ordering",
	},
}

// callOffset returns the source offset of the first call to name inside fn.
func callOffset(t *testing.T, root string, file, fn, name string) (int, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		off := -1
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var ident string
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				ident = fun.Name
			case *ast.SelectorExpr:
				ident = fun.Sel.Name
			}
			if ident == name && off == -1 {
				off = fset.Position(call.Pos()).Offset
				return false
			}
			return true
		})
		if off == -1 {
			return 0, false
		}
		return off, true
	}
	t.Fatalf("%s: function %s not found -- the ordering inventory is stale", file, fn)
	return 0, false
}

// TestT1ForcedRollbackStepOrder fails if the header-index removal is ever moved back
// ahead of the steps it must follow.
func TestT1ForcedRollbackStepOrder(t *testing.T) {
	root := repoRoot(t)
	for _, oc := range t1RequiredOrder {
		oc := oc
		t.Run(oc.fn+"__"+oc.first+"_before_"+oc.last, func(t *testing.T) {
			firstOff, ok := callOffset(t, root, oc.file, oc.fn, oc.first)
			if !ok {
				t.Fatalf("ORDERING INVENTORY STALE: %s.%s no longer calls %s",
					oc.file, oc.fn, oc.first)
			}
			lastOff, ok := callOffset(t, root, oc.file, oc.fn, oc.last)
			if !ok {
				t.Fatalf("ORDERING INVENTORY STALE: %s.%s no longer calls %s",
					oc.file, oc.fn, oc.last)
			}
			if lastOff < firstOff {
				t.Fatalf("ROLLBACK-ATOMICITY REGRESSION: in %s.%s the call to %s now "+
					"precedes %s (offsets %d < %d).\n%s",
					oc.file, oc.fn, oc.last, oc.first, lastOff, firstOff, oc.why)
			}
		})
	}
}
