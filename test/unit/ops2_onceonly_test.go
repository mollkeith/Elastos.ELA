// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- OPS2 item 4: ONCE, AND ONLY ONCE.
//
// The forced rollback is a one-time, destructive operation on a live chain holding
// real value. The owner's requirement is that the binary establish this for itself,
// with extra verification, so that "people do not keep getting sent back to the same
// rollback height".
//
// This file is the measurement, not an assumption. It walks every store state a real
// node can boot in and records, through the PRODUCTION entry points main.go calls,
// whether the rewind arms, whether the node refuses, and whether it says anything.
// TestOps2OnceOnlyTruthTable is the table itself; the tests around it pin the two
// cells that carry the property.
//
// MEASURED RESULT (canonical tree 8e78ce3): the once-only property is STRUCTURAL, not
// bolted on. Arming requires the block at ForcedRollbackHeight+1 to hash to the
// configured trigger, and a rewind is exactly the operation that removes that block,
// so the predicate that authorises the rewind is falsified BY the rewind. Nothing
// short of putting the removed block back can re-arm it. What was missing was not a
// guard but a STATEMENT: on a node whose rollback is already applied, every check in
// the boot path returns nil in silence, so an operator has only the absence of output
// to go on.
package unit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/database"
)

// ops2Mine appends one block at chain tip+1 whose timestamp carries `salt`, so a
// re-mined block at the same height is guaranteed a DIFFERENT hash from the one the
// rollback discarded. It writes through the same store path t1BuildChain uses --
// StoreBlock, SaveBlock, then the persisted block-header index row -- so the block
// survives the reopen that follows.
func ops2Mine(t *testing.T, chain *blockchain.BlockChain, salt uint32) common.Uint256 {
	t.Helper()
	h := chain.GetHeight() + 1
	prev := *chain.BestChain.Hash
	blk := &types.Block{
		Header: common2.Header{
			Version: 0, Height: h, Previous: prev,
			Timestamp: 1700000000 + h + salt, Bits: 0x1d03ffff,
		},
		Transactions: []interfaces.Transaction{residueCoinbase(h)},
	}
	hash := blk.Hash()
	node, err := chain.LoadBlockNode(&blk.Header, &hash)
	if err != nil {
		t.Fatalf("LoadBlockNode %d: %v", h, err)
	}
	buf := new(bytes.Buffer)
	if err := (&types.DposBlock{Block: blk}).Serialize(buf); err != nil {
		t.Fatalf("serialize %d: %v", h, err)
	}
	if err := chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(hash, buf.Bytes())
	}); err != nil {
		t.Fatalf("StoreBlock %d: %v", h, err)
	}
	if err := chain.GetDB().SaveBlock(blk, node, nil,
		blockchain.CalcPastMedianTime(node)); err != nil {
		t.Fatalf("SaveBlock %d: %v", h, err)
	}
	chain.SetTip(node)
	chain.BestChain = node
	if err := chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
		hdr, herr := chain.GetDB().GetFFLDB().GetHeader(hash)
		if herr != nil {
			return herr
		}
		return blockchain.DBStoreBlockNode(dbTx, hdr, 3)
	}); err != nil {
		t.Fatalf("DBStoreBlockNode %d: %v", h, err)
	}
	return hash
}

// ops2Boot is one simulated node boot: it opens the store the way main.go does and
// runs, in main.go's order, the checks that decide whether this node rolls back.
type ops2Boot struct {
	Armed    bool
	Refused  error
	Rewound  bool
	Tip      uint32
	Stderr   string
	AtPlusOn common.Uint256
}

// ops2BootOnce replays main.go's forced-rollback boot sequence over dir at a QUIETED
// log level, capturing everything the operator would actually see.
//
// The sequence is main.go's, in main.go's order: CheckAbandonedForcedRollback,
// ForcedRollbackArmed, then either (PreflightForcedRollback, ForceRollback) or
// CheckForcedRollbackResidue, then VerifyForcedRollbackApplied.
func ops2BootOnce(t *testing.T, dir string, params *config.Configuration) ops2Boot {
	t.Helper()
	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	var b ops2Boot
	got := ops2CaptureConsole(t, ops2QuietLevel, func() {
		if err := chain.CheckAbandonedForcedRollback(); err != nil {
			b.Refused = err
			return
		}
		armed, err := chain.ForcedRollbackArmed()
		if err != nil {
			b.Refused = err
			return
		}
		b.Armed = armed
		if armed {
			if err := chain.PreflightForcedRollback(); err != nil {
				b.Refused = err
				return
			}
			if err := chain.ForceRollback(nil); err != nil {
				b.Refused = err
				return
			}
			b.Rewound = true
		} else if params.ForcedRollbackTrigger != "" &&
			params.ForcedRollbackHeight != 0 &&
			params.ForcedRollbackHeight != config.DisabledForcedRollbackHeight {
			if err := chain.CheckForcedRollbackResidue(); err != nil {
				b.Refused = err
				return
			}
		}
		if err := chain.VerifyForcedRollbackApplied(); err != nil {
			b.Refused = err
			return
		}
	})
	b.Stderr = got.Stderr
	b.Tip = chain.GetHeight()
	if h, err := chain.GetBlockHash(params.ForcedRollbackHeight + 1); err == nil {
		b.AtPlusOn = h
	}
	return b
}

// TestOps2OnceOnlyTruthTable is the (store state x config) -> (arms / refuses /
// silent) table the owner asked for. Every row drives the production boot sequence.
func TestOps2OnceOnlyTruthTable(t *testing.T) {
	const target = uint32(5)

	type row struct {
		name string
		// setup returns the data dir and the params the boot runs with.
		setup func(t *testing.T) (string, *config.Configuration)
		// wantArmed / wantRefused are the cells this table asserts.
		wantArmed   bool
		wantRefused bool
		// wantLoud requires the boot to have said SOMETHING on stderr. A cell that
		// is neither armed nor refused nor loud is a silent cell, and a silent cell
		// on a one-shot destructive operation is the defect this file exists for.
		wantLoud bool
		// wantPhrase is the statement this cell must actually make. "Loud" alone is
		// too weak an assertion: it passes for any output at all, including the
		// wrong cell's message.
		wantPhrase string
		// wantRefusalPhrase is the same requirement for a cell that REFUSES. A
		// refusal is returned rather than printed here; in production every one of
		// them reaches the operator through main.go's printErrorAndExit, which the
		// root package's ops2_fatal_test.go proves is audible at every print level.
		wantRefusalPhrase string
	}

	rows := []row{
		{
			name: "A/holds-the-removed-chain/armed-config",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				return dir, p
			},
			wantArmed: true, wantRefused: false, wantLoud: true,
			wantPhrase: "rewinding chain store from height",
		},
		{
			name: "B/already-rewound/sitting-at-target",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				return dir, p
			},
			wantArmed: false, wantRefused: false, wantLoud: true,
			wantPhrase: "nothing to roll back on this node",
		},
		{
			name: "C/already-rewound/moved-forward-on-the-recovered-chain",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				func() {
					chain, store := t1Open(t, dir, p, nil, nil)
					defer t1Close(store)
					for i := uint32(0); i < 3; i++ {
						ops2Mine(t, chain, 7777)
					}
				}()
				return dir, p
			},
			wantArmed: false, wantRefused: false, wantLoud: true,
			wantPhrase: "ALREADY APPLIED",
		},
		{
			name: "D/fresh-node-below-the-target",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				// Build the real chain elsewhere so the trigger is a real hash,
				// then sync only part way in the dir under test.
				ref := t.TempDir()
				refParams := t1Params(target)
				t1BuildChain(t, ref, refParams, target+3)
				t1BuildChain(t, dir, p, target-2)
				p.ForcedRollbackTrigger = refParams.ForcedRollbackTrigger
				return dir, p
			},
			wantArmed: false, wantRefused: false, wantLoud: true,
			wantPhrase: "nothing to roll back on this node",
		},
		{
			name: "E/old-backup-restored-after-the-restart",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				// The operator restores a pre-rollback copy of the data directory:
				// rebuild the identical chain over the same dir.
				t1BuildChain(t, dir, p, target+3)
				return dir, p
			},
			wantArmed: true, wantRefused: false, wantLoud: true,
			wantPhrase: "rewinding chain store from height",
		},
		{
			name: "F/holds-the-removed-chain/rollback-not-configured",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				p.ForcedRollbackTrigger = ""
				p.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
				return dir, p
			},
			wantArmed: false, wantRefused: false, wantLoud: false,
		},
		{
			// The band 48/48 rehearsal nodes landed in: too far past the target for
			// the incremental rewind. It must refuse rather than boot on the removed
			// chain, and the refusal must not prescribe a disarm mainnet discards.
			name: "G/holds-the-removed-chain/beyond-the-rewind-window",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+b1b5CapacityDepth)
				return dir, p
			},
			wantArmed: true, wantRefused: true, wantLoud: true,
			wantRefusalPhrase: "NO disarm on mainnet",
		},
		{
			// The typo cell: a trigger naming a healthy block at another height.
			name: "H/healthy-store/trigger-names-the-wrong-block",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				hashes := t1BuildChain(t, dir, p, target+3)
				p.ForcedRollbackTrigger = hashes[target+3].ReversedString()
				return dir, p
			},
			wantArmed: false, wantRefused: true, wantLoud: false,
			wantRefusalPhrase: "CONFIGURATION ERROR",
		},
		{
			// The disarm trap: a rewind started, did not finish, and the operator
			// then removed the trigger. Starting here is how a node rejoins on the
			// removed chain unnoticed, so it must refuse.
			name: "I/interrupted-rewind/operator-then-disarmed",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				func() {
					chain, store := t1Open(t, dir, p, nil, nil)
					defer t1Close(store)
					stop := make(chan struct{})
					close(stop)
					if err := chain.ForceRollback(stop); err == nil {
						t.Fatal("harness is wrong: the rewind was not interrupted")
					}
				}()
				disarmed := t1Params(target)
				disarmed.ForcedRollbackTrigger = ""
				disarmed.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
				return dir, disarmed
			},
			wantArmed: false, wantRefused: true, wantLoud: false,
			wantRefusalPhrase: "in-progress rollback this node is not configured to finish",
		},
	}

	var table strings.Builder
	table.WriteString("\nOPS2 once-only truth table (production boot sequence)\n")
	fmt.Fprintf(&table, "%-52s %-6s %-8s %-8s %-6s %s\n",
		"store state x config", "armed", "rewound", "refused", "tip", "loud")

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			dir, params := r.setup(t)
			b := ops2BootOnce(t, dir, params)
			loud := strings.TrimSpace(b.Stderr) != ""
			fmt.Fprintf(&table, "%-52s %-6v %-8v %-8v %-6d %v\n",
				r.name, b.Armed, b.Rewound, b.Refused != nil, b.Tip, loud)

			if b.Armed != r.wantArmed {
				t.Errorf("armed=%v want %v", b.Armed, r.wantArmed)
			}
			if (b.Refused != nil) != r.wantRefused {
				t.Errorf("refused=%v want %v (err=%v)", b.Refused != nil,
					r.wantRefused, b.Refused)
			}
			if loud != r.wantLoud {
				t.Errorf("loud=%v want %v; stderr was:\n%s", loud, r.wantLoud, b.Stderr)
			}
			if r.wantPhrase != "" && !strings.Contains(b.Stderr, r.wantPhrase) {
				t.Errorf("this cell did not make its statement (%q missing); "+
					"stderr was:\n%s", r.wantPhrase, b.Stderr)
			}
			if r.wantRefusalPhrase != "" {
				if b.Refused == nil {
					t.Errorf("this cell must refuse with %q", r.wantRefusalPhrase)
				} else if !strings.Contains(b.Refused.Error(), r.wantRefusalPhrase) {
					t.Errorf("the refusal does not say %q; it said:\n%v",
						r.wantRefusalPhrase, b.Refused)
				}
			}
		})
	}
	t.Log(table.String())
}

// TestOps2RewindFalsifiesItsOwnArmingPredicate is the STRUCTURAL proof of once-only,
// by execution rather than by reading the code.
//
// It boots the same data directory three times in a row with the rollback configured
// and armed, and asserts the rewind runs on the first boot and on no later one -- and
// that after the chain re-mines a different block at target+1 the predicate is still
// false. This passes on pristine, and that is the point: it is the evidence for the
// claim that no new machinery is needed to make the rollback fire once.
func TestOps2RewindFalsifiesItsOwnArmingPredicate(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)
	discarded := params.ForcedRollbackTrigger

	first := ops2BootOnce(t, dir, params)
	if !first.Armed || !first.Rewound {
		t.Fatalf("boot 1: armed=%v rewound=%v, want both true (err=%v)",
			first.Armed, first.Rewound, first.Refused)
	}
	if first.Tip != target {
		t.Fatalf("boot 1: tip %d, want %d", first.Tip, target)
	}

	for i := 2; i <= 3; i++ {
		b := ops2BootOnce(t, dir, params)
		if b.Armed || b.Rewound {
			t.Fatalf("boot %d: the rollback re-armed on a node it had already "+
				"rewound (armed=%v rewound=%v)", i, b.Armed, b.Rewound)
		}
		if b.Refused != nil {
			t.Fatalf("boot %d refused: %v", i, b.Refused)
		}
	}

	// The chain moves on: a DIFFERENT block is mined at the height the discarded one
	// occupied. This is the state every node in the fleet is in a few minutes after
	// the restart, and it is the state that must never re-arm.
	func() {
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		for i := uint32(0); i < 3; i++ {
			ops2Mine(t, chain, 4242)
		}
	}()

	after := ops2BootOnce(t, dir, params)
	if after.Armed || after.Rewound {
		t.Fatalf("the rollback re-armed once the chain had moved past the target "+
			"(armed=%v rewound=%v)", after.Armed, after.Rewound)
	}
	if after.Tip <= target {
		t.Fatalf("the chain did not move forward: tip %d", after.Tip)
	}
	if after.AtPlusOn.ReversedString() == discarded {
		t.Fatal("harness is wrong: the re-mined block has the discarded block's hash")
	}
}

// TestOps2AppliedRollbackStatesItselfAffirmatively is the "extra verification" half.
//
// A node whose rollback is already applied and whose chain has moved on takes every
// early return in the boot path and says NOTHING. The operator has only an absence of
// output to distinguish "this node rolled back and is safe" from "this binary never
// looked". The requirement is a POSITIVE statement, backed by evidence read from the
// store rather than from a flag.
//
// FAILS ON PRISTINE: VerifyForcedRollbackApplied returns nil silently when the
// trigger is absent.
func TestOps2AppliedRollbackStatesItselfAffirmatively(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)
	discarded := params.ForcedRollbackTrigger

	ops2BootOnce(t, dir, params)
	func() {
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		for i := uint32(0); i < 3; i++ {
			ops2Mine(t, chain, 4242)
		}
	}()

	b := ops2BootOnce(t, dir, params)
	if b.Refused != nil {
		t.Fatalf("boot refused: %v", b.Refused)
	}
	for _, want := range []string{
		// names the trigger the operator can check against the release notes
		discarded,
		// the evidence: it is gone from every persisted index
		"main-chain index",
		"block-header index",
		"raw block store",
		// and the conclusion, in words an operator can act on
		"will not",
	} {
		if !strings.Contains(b.Stderr, want) {
			t.Errorf("an already-rolled-back node never states that it is rolled back: "+
				"missing %q.\nstderr was:\n%s", want, b.Stderr)
		}
	}
}
