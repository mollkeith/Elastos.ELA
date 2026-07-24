// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// STRUCTURAL backstop for batch t3-dos (FV-15, FV-17, FV-14, NX-07, NX-04).
//
// The behavioural fail-on-pristine tests live with their packages and drive the
// real entry points:
//   - mempool/fv15_blockpool_bounds_test.go   (AppendDposBlock, AddToBlockMap)
//   - mempool/nx07_smallcross_store_test.go   (doRemoveTransaction, onPopBack)
//   - p2p/peer/fv17_backlog_and_ping_test.go  (QueueMessage/queueHandler, handlePingMsg)
//   - dpos/p2p/hub/fv14_handshake_deadline_test.go (Hub.Intercept, WrapConn)
//   - core/transaction/nx04_claimnode_ownerkeyspace_test.go (SpecialContextCheck)
//
// Three of those packages are outside the eight consensus suites, and two of
// them (p2p/peer, dpos/p2p) cannot be run recursively on a box where a live node
// holds their ports. This file puts the same inventory inside test/unit, which
// IS one of the eight, so a merge that silently drops a guard is caught by the
// standard suite run.
//
// It asserts the PARENT LINKS as well as the guards themselves: severing
// cleanTransactions -> doRemoveTransaction, for example, disarms NX-07 without
// touching the NX-07 call site at all.
package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// t3Edge is one required production edge: within `file`, function `fn` must
// contain a call to `callee`.
type t3Edge struct {
	finding string
	file    string
	fn      string
	callee  string
	why     string
}

var t3RequiredEdges = []t3Edge{
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "appendBlock",
		callee: "retentionWindowContains",
		why:    "the admission height bound; without it any height is poolable for free",
	},
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "appendBlock",
		callee: "putBlockLocked",
		why:    "count/byte caps are enforced on insert, not by the sweep",
	},
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "appendBlockAndConfirm",
		callee: "putBlockLocked",
		why:    "the block+confirm path is the second unbounded admission path",
	},
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "AddToBlockMap",
		callee: "putBlockLocked",
		why:    "the unvalidated admission path; nothing but the cap bounds it",
	},
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "putBlockLocked",
		callee: "pruneLocked",
		why:    "makes the sweep self-driving; its only other caller is the block-connected path",
	},
	{
		finding: "FV-15", file: "mempool/blockpool.go", fn: "pruneLocked",
		callee: "retentionWindowContains",
		why:    "admission and retention must read the SAME window or the bound drifts",
	},
	{
		finding: "NX-07", file: "mempool/txpool.go", fn: "doRemoveTransaction",
		callee: "cleanSmallCrossTransferRecord",
		why:    "conflict eviction + the post-reorg re-check both funnel through here",
	},
	{
		finding: "NX-07", file: "mempool/txpool.go", fn: "onPopBack",
		callee: "cleanSmallCrossTransferRecord",
		why:    "fee-ordered eviction; F-120 cleaned the in-memory twins only",
	},
	{
		finding: "NX-07", file: "mempool/txpool.go", fn: "cleanSmallCrossTransferRecord",
		callee: "CleanSmallCrossTransferTx",
		why:    "the persistent delete itself",
	},
	{
		finding: "NX-07 (parent link)", file: "mempool/txpool.go", fn: "cleanTransactions",
		callee: "doRemoveTransaction",
		why:    "severing this disarms NX-07 without touching its call site",
	},
	{
		finding: "NX-07 (parent link)", file: "mempool/txpool.go", fn: "checkAndCleanAllTransactions",
		callee: "doRemoveTransaction",
		why:    "the third leak path, the one the original report missed",
	},
	{
		finding: "NX-07", file: "blockchain/chainstore.go", fn: "SaveSmallCrossTransferTx",
		callee: "censusSmallCrossTransferTxsLocked",
		why:    "the bucket cap needs the census to be seeded before it can refuse",
	},
	{
		finding: "NX-04", file: "core/transaction/crcouncilmemberclaimnodetransaction.go",
		fn:     "SpecialContextCheck",
		callee: "checkClaimedNodeKeyOutsideOwnerKeyspace",
		why:    "the owner-keyspace guard, in both payload-version arms",
	},
	{
		finding: "NX-04", file: "core/transaction/crcouncilmemberclaimnodetransaction.go",
		fn:     "checkClaimedNodeKeyOutsideOwnerKeyspace",
		callee: "ProducerOwnerPublicKeyExists",
		why:    "the sibling producer validators' own predicate; a different one would not catch it",
	},
	{
		finding: "FV-14", file: "dpos/p2p/hub/conn.go", fn: "WrapConn",
		callee: "SetDeadline",
		why:    "the only bound on a pre-identity DPoS hub connection",
	},
	{
		finding: "FV-14 (parent link)", file: "dpos/p2p/hub/hub.go", fn: "Intercept",
		callee: "WrapConn",
		why:    "Intercept is the top of dpos/p2p/server.inboundPeerConnected",
	},
	{
		finding: "FV-17", file: "p2p/peer/peer.go", fn: "handlePingMsg",
		callee: "allowPingResponseLocked",
		why:    "ping is the unmetered 1:1 amplifier; it accrues no ban score anywhere",
	},
}

// t3FuncDecl finds the (possibly method) declaration named fn in file.
func t3FuncDecl(t *testing.T, root string, e t3Edge) *ast.FuncDecl {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, e.file), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("[%s] cannot parse %s: %v", e.finding, e.file, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Name.Name == e.fn && fd.Body != nil {
			return fd
		}
	}
	t.Fatalf("[%s] %s: function %s not found — the inventory is stale, or the "+
		"production function was renamed away from its guard", e.finding, e.file, e.fn)

	return nil
}

func t3CalleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}

	return ""
}

// TestT3DosGuardsAreWired fails on a DELETED CALL, which is the mutation class
// a reviewer is most likely to wave through.
func TestT3DosGuardsAreWired(t *testing.T) {
	root := repoRoot(t)

	for _, e := range t3RequiredEdges {
		e := e
		t.Run(strings.ReplaceAll(e.finding, " ", "_")+"__"+e.fn+"__"+e.callee, func(t *testing.T) {
			fd := t3FuncDecl(t, root, e)

			var found bool
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if t3CalleeName(call) == e.callee {
					found = true
					return false
				}
				return true
			})

			if !found {
				t.Fatalf("[%s] %s: %s no longer calls %s — %s",
					e.finding, e.file, e.fn, e.callee, e.why)
			}
		})
	}
}

// TestFV17PeerWriteDeadlineIsNotTheTenMinuteOne is a source-level assertion
// because the constant lives in a package the eight suites do not run. The peer
// write path must not go back to p2p.WriteMessageTimeOut: that ten minute
// window is how long a peer that stopped reading could pin a connection and
// everything queued behind it.
func TestFV17PeerWriteDeadlineIsNotTheTenMinuteOne(t *testing.T) {
	root := repoRoot(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "p2p/peer/peer.go"), nil,
		parser.AllErrors)
	if err != nil {
		t.Fatalf("cannot parse p2p/peer/peer.go: %v", err)
	}

	var checked bool
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "writeMessage" || fd.Body == nil {
			continue
		}
		checked = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "p2p" && sel.Sel.Name == "WriteMessageTimeOut" {
				t.Fatalf("FV-17: p2p/peer writeMessage went back to the ten " +
					"minute p2p.WriteMessageTimeOut")
			}
			return true
		})
	}
	if !checked {
		t.Fatal("p2p/peer/peer.go has no writeMessage function — inventory stale")
	}
}

// TestFV15BlockPoolHasBothBounds asserts the pool still declares a COUNT bound
// and a BYTE bound. The count cap alone still concedes
// maxPooledBlocks x MaxBlockContextSize of RAM, which is the substitution the
// whole finding is about: count and height bounds standing in for byte bounds
// on an unauthenticated admission path.
func TestFV15BlockPoolHasBothBounds(t *testing.T) {
	root := repoRoot(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "mempool/blockpool.go"), nil,
		parser.AllErrors)
	if err != nil {
		t.Fatalf("cannot parse mempool/blockpool.go: %v", err)
	}

	want := map[string]bool{"maxPooledBlocks": false, "maxPooledBlockBytes": false}
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if _, tracked := want[id.Name]; tracked {
			want[id.Name] = true
		}
		return true
	})

	for name, seen := range want {
		if !seen {
			t.Fatalf("FV-15: mempool/blockpool.go no longer declares %s", name)
		}
	}
}
