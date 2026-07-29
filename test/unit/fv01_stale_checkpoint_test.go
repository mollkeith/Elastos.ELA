// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package unit

import (
	"go/ast"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/stretchr/testify/assert"
)

// fv01Checkpoint is a minimal ICheckPoint that records which block heights the
// manager actually handed it, so a FROZEN checkpoint is directly observable.
type fv01Checkpoint struct {
	height    uint32
	processed []uint32
	resets    int
}

func (c *fv01Checkpoint) Key() string                      { return "cp_fv01" }
func (c *fv01Checkpoint) GetHeight() uint32                { return c.height }
func (c *fv01Checkpoint) SetHeight(h uint32)               { c.height = h }
func (c *fv01Checkpoint) SavePeriod() uint32               { return 1000 }
func (c *fv01Checkpoint) SaveStartHeight() uint32          { return 0 }
func (c *fv01Checkpoint) EffectivePeriod() uint32          { return 720 }
func (c *fv01Checkpoint) StartHeight() uint32              { return 0 }
func (c *fv01Checkpoint) DataExtension() string            { return ".fv01" }
func (c *fv01Checkpoint) Priority() checkpoint.Priority    { return checkpoint.Medium }
func (c *fv01Checkpoint) LogError(err error)               {}
func (c *fv01Checkpoint) OnInit()                          {}
func (c *fv01Checkpoint) OnRollbackTo(height uint32) error { return nil }
func (c *fv01Checkpoint) OnRollbackSeekTo(height uint32)   {}
func (c *fv01Checkpoint) Serialize(w io.Writer) error      { return nil }
func (c *fv01Checkpoint) Deserialize(r io.Reader) error    { return nil }
func (c *fv01Checkpoint) Snapshot() checkpoint.ICheckPoint { return c }
func (c *fv01Checkpoint) Generator() func([]byte) checkpoint.ICheckPoint {
	return func([]byte) checkpoint.ICheckPoint { return c }
}

func (c *fv01Checkpoint) OnBlockSaved(block *types.DposBlock) {
	c.processed = append(c.processed, block.Height)
}

// OnReset is the genesis rebuild: the derived state is thrown away.
func (c *fv01Checkpoint) OnReset() error {
	c.processed = nil
	c.resets++
	return nil
}

// The production discard logs loudly, and the process-wide logger is nil until some
// entry point installs one, so install a throwaway file logger for this package.
func init() { log.NewDefault(filepath.Join(os.TempDir(), "ela-fv01-test-logs"), 5, 0, 0) }

func fv01Block(height uint32) *types.DposBlock {
	return &types.DposBlock{Block: &types.Block{Header: common2.Header{Height: height}}}
}

// TestFV01StaleCheckpointFreezesAndIsDiscarded is the fail-on-pristine proof of
// FV-01, driven through the real production checkpoint manager.
//
// A checkpoint's Height is never LOWERED: Manager.OnRollbackTo forwards to each
// ICheckPoint.OnRollbackTo and never calls SetHeight, no OnReset implementation
// zeroes it, and loadCheckpointFile writes the FILE's height straight into the live
// object. So after the deep-reset branch restores a default snapshot written on an
// ABANDONED branch, the live checkpoint can sit ABOVE the post-detach best height --
// and Manager.onBlockSaved skips every block with `block.Height <= v.GetHeight()`.
// Both the InitCheckpoint replay AND the attach loop then become complete no-ops for
// that checkpoint: derived DPoS/CR state FREEZES on abandoned-branch state while the
// block store follows the canonical chain.
//
// FAIL-ON-PRISTINE: without DiscardStaleCheckpoints the second replay is still a
// no-op and `processed` stays empty forever.
func TestFV01StaleCheckpointFreezesAndIsDiscarded(t *testing.T) {
	m := checkpoint.NewManager(config.GetDefaultParams())
	cp := &fv01Checkpoint{height: 200} // an abandoned-branch snapshot, restored from disk
	m.Register(cp)
	defer m.Close()

	const bestHeight = uint32(100) // the post-detach canonical tip

	// The replay after the deep reset. Every block is silently skipped.
	for h := uint32(1); h <= bestHeight; h++ {
		m.OnBlockSaved(fv01Block(h), nil, false, 0, true)
	}
	assert.Equal(t, 0, len(cp.processed),
		"sanity: this is the FREEZE -- a checkpoint above the tip processes nothing")
	assert.Equal(t, uint32(200), cp.GetHeight(),
		"sanity: nothing in the rollback/reset path ever lowers the height")

	// The fix: discard the checkpoint that is ahead of the chain it describes.
	assert.NoError(t, m.DiscardStaleCheckpoints(bestHeight))

	assert.Equal(t, uint32(0), cp.GetHeight(),
		"FV-01: a checkpoint above the post-detach best height must be reset to 0 so "+
			"the replay can rebuild it")
	assert.Equal(t, 1, cp.resets, "FV-01: the stale checkpoint must be rebuilt from genesis")

	// Replay again: now it actually rebuilds.
	for h := uint32(1); h <= bestHeight; h++ {
		m.OnBlockSaved(fv01Block(h), nil, false, 0, true)
	}
	assert.Equal(t, int(bestHeight), len(cp.processed),
		"FV-01: after the discard the replay must rebuild derived state block by block "+
			"(pristine stays frozen and processes nothing)")
}

// TestFV01HealthyCheckpointIsNotDiscarded is the negative control. Discarding
// unconditionally would force a replay from StartHeight (~2M blocks on mainnet,
// hours, under the chain lock) on EVERY deep reorg, so the condition
// `GetHeight() > bestHeight` is load-bearing, not decoration.
func TestFV01HealthyCheckpointIsNotDiscarded(t *testing.T) {
	m := checkpoint.NewManager(config.GetDefaultParams())
	cp := &fv01Checkpoint{height: 90}
	m.Register(cp)
	defer m.Close()

	assert.NoError(t, m.DiscardStaleCheckpoints(100))

	assert.Equal(t, uint32(90), cp.GetHeight(),
		"a checkpoint at or below the best height describes common ancestry and must be kept")
	assert.Equal(t, 0, cp.resets, "no rebuild may be forced for a healthy checkpoint")

	// Boundary: exactly at the best height is still healthy.
	cp.height = 100
	assert.NoError(t, m.DiscardStaleCheckpoints(100))
	assert.Equal(t, uint32(100), cp.GetHeight())
	assert.Equal(t, 0, cp.resets)
}

// TestFV01DeepResetErrorIsNotDiscarded asserts the second half of FV-01 that no
// behavioural test in this tree can reach cheaply: reorganizeChain used to call
// InitCheckpoint(nil,nil,nil) and THROW THE ERROR AWAY, so a failed derived-state
// rebuild let the reorg continue with unknown DPoS/CR state.
//
// The structural inventory in wiring_callsites_test.go can prove the call exists but
// not that its error is returned -- an `_ =` would satisfy it. This walks the AST of
// reorganizeChain and requires the call to appear inside an `if err := ...; err != nil
// { return ... }` statement.
//
// FAIL-ON-PRISTINE: the pristine statement is a bare ExprStmt, which fails here.
func TestFV01DeepResetErrorIsNotDiscarded(t *testing.T) {
	root := repoRoot(t)
	fd, _ := funcBody(t, root, callSite{
		file: "blockchain/blockchain.go", fn: "reorganizeChain",
		callee: "InitCheckpointAfterDeepReset",
	})

	guarded := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// The assigned name must be a real variable, not the blank identifier.
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
				return true
			}
		}
		calls := false
		ast.Inspect(assign, func(in ast.Node) bool {
			call, ok := in.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
				sel.Sel.Name == "InitCheckpointAfterDeepReset" {
				calls = true
				return false
			}
			return true
		})
		if !calls {
			return true
		}
		// ... and the body must return.
		ast.Inspect(ifStmt.Body, func(in ast.Node) bool {
			if _, ok := in.(*ast.ReturnStmt); ok {
				guarded = true
				return false
			}
			return true
		})
		return true
	})

	if !guarded {
		t.Fatal("FV-01: reorganizeChain must CHECK and RETURN the deep-reset rebuild error " +
			"(pristine discarded it and continued the reorg with unknown derived state)")
	}
}
