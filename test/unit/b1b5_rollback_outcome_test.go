// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- TIER 1 fail-on-pristine proof for the restart-day defect in the
// forced-rollback boot path: ARMED WAS READ AS APPLIED (B1), and the armed path had
// no pre-flight store scan (B5).
//
// Every test drives the PRODUCTION functions main.go calls --
// (*BlockChain).ForcedRollbackArmed, (*BlockChain).PreflightForcedRollback,
// (*BlockChain).ForceRollback and (*BlockChain).VerifyForcedRollbackApplied --
// against a real ffldb-backed store, and boots the way main.go boots (close both
// stores, reopen, let blockchain.New rebuild b.Nodes from the persisted block-header
// index). The structural half of the proof lives in wiring_callsites_test.go: delete
// either call site from main.go and the inventory names the finding it disarmed, and
// re-introducing the swallowed capacity branch is caught by the negative inventory.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 4667fdf):
//
//   - B1: with tip = target+720 the rewind returns ErrForcedRollbackExceedsCapacity;
//     main.go:199-205 logged it and CONTINUED BOOTING. The store then still held the
//     trigger block main-chain indexed, header-rowed and fetchable, i.e. the node came
//     up on the exploit chain. Neither shipped safety net saw it: the height check was
//     tautological, and the checkpoint-baseline check only fires when a RESTORED
//     snapshot sits at/above the target, which for this depth band it does not.
//   - B5: on a store whose header rows above the target were eaten by an earlier
//     interrupted rollback, the armed path went straight into ForceRollback, which
//     got as far as the first block and then died on an INTERNAL INDEX ASSERTION --
//     "assertion failed: dbIndexDisconnectBlock must be called with the block at the
//     current index tip (transaction index, tip <hash>, block <hash>)". No sentinel,
//     no classification, no remedy: the operator is handed two raw hashes and a
//     node that will not start, at the point in restart day where that costs the
//     most. Reproduced verbatim in the `pristine-sequence-fails-opaquely` subtest.
package unit

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/database"
)

// b1b5CapacityDepth is the rewind depth at which ForceRollback declines; it equals
// blockchain's unexported maxHistoryCapacity. The test asserts the decline really
// happens rather than assuming it, so a change to that constant surfaces here.
const b1b5CapacityDepth = 720

// b1b5Locate probes the persisted store for the trigger block through the production
// entry point.
func b1b5Locate(t *testing.T, chain *blockchain.BlockChain) *blockchain.ForcedRollbackTriggerLocation {
	t.Helper()
	loc, err := chain.LocateForcedRollbackTrigger()
	if err != nil {
		t.Fatalf("LocateForcedRollbackTrigger: %v", err)
	}
	if loc == nil {
		t.Fatal("forced rollback is not configured on the test params -- harness is wrong")
	}
	return loc
}

// b1b5ReadRaw returns the serialized bytes of a block as they sit in the raw by-hash
// store, so residue #2 can be re-created byte-for-byte later.
func b1b5ReadRaw(t *testing.T, chain *blockchain.BlockChain, hash common.Uint256) []byte {
	t.Helper()
	blk, err := chain.GetDB().GetFFLDB().GetBlock(hash)
	if err != nil {
		t.Fatalf("read raw block %s: %v", hash.String(), err)
	}
	buf := new(bytes.Buffer)
	if err := blk.Serialize(buf); err != nil {
		t.Fatalf("serialize block %s: %v", hash.String(), err)
	}
	return buf.Bytes()
}

// b1b5RestoreRaw puts those exact bytes back into the raw by-hash store without
// touching any index, which is exactly the residue #2 shape.
func b1b5RestoreRaw(t *testing.T, chain *blockchain.BlockChain,
	hash common.Uint256, raw []byte) {
	t.Helper()
	if err := chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(hash, raw)
	}); err != nil {
		t.Fatalf("restore raw entry %s: %v", hash.String(), err)
	}
}

// TestB1CapacityDeclinedNodeMustNotBootOnTheExploitChain is the primary B1 proof.
//
// It builds the depth band the rehearsal names -- tip more than the incremental
// rewind window above the target, so the rewind is DECLINED -- and asserts the facts
// that together are the defect:
//
//  1. the node is still ARMED and the rewind returned the capacity sentinel;
//  2. the persisted store still holds the trigger block on the MAIN CHAIN, i.e.
//     "armed" was true while "applied" was false;
//  3. the shipped checkpoint-baseline safety net does NOT fire in this band, so
//     pristine main.go had nothing left to stop it and the node booted;
//  4. the fix refuses, loudly and with a working remedy.
//
// FAILS ON PRISTINE at (4): pristine has no VerifyForcedRollbackApplied, and
// pristine main.go swallowed the sentinel from (1) instead of exiting. Deleting
// either production call site from main.go is caught by wiring_callsites_test.go.
func TestB1CapacityDeclinedNodeMustNotBootOnTheExploitChain(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	tip := target + b1b5CapacityDepth
	t1BuildChain(t, dir, params, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	// (1) ARMED -- this node holds the chain the rollback targets.
	armed, err := chain.ForcedRollbackArmed()
	if err != nil {
		t.Fatalf("ForcedRollbackArmed: %v", err)
	}
	if !armed {
		t.Fatal("harness broken: the node must be armed at tip target+720")
	}

	// The pre-flight must PASS here: this store is healthy, it is only too deep. A
	// pre-flight that failed would mask the capacity decision this test is about.
	if e := chain.PreflightForcedRollback(); e != nil {
		t.Fatalf("pre-flight must pass on a healthy but too-deep store, got: %v", e)
	}

	rbErr := chain.ForceRollback(nil)
	if !errors.Is(rbErr, blockchain.ErrForcedRollbackExceedsCapacity) {
		t.Fatalf("harness broken: depth %d must return the capacity sentinel, got %v",
			b1b5CapacityDepth, rbErr)
	}
	// FV-18: the remedy must be the form that actually does something. MEASURED on
	// this tree, `ela-cli rollback <N>` (positional, the form the pristine string
	// printed) prints the subcommand help and exits 0 without touching the store.
	if !strings.Contains(rbErr.Error(), "ela-cli rollback --height") {
		t.Fatalf("FV-18: the capacity remedy must print the --height FLAG form, got: %v", rbErr)
	}

	// (2) ARMED IS NOT APPLIED. The rewind did not happen, and the store says so.
	if got := chain.GetHeight(); got != tip {
		t.Fatalf("the declined rewind must leave the tip untouched, got %d want %d", got, tip)
	}
	loc := b1b5Locate(t, chain)
	if !loc.OnMainChain {
		t.Fatalf("harness broken: the trigger block must still be main-chain indexed "+
			"after a declined rewind, got %s", loc.String())
	}
	if loc.MainChainHeight != target+1 {
		t.Fatalf("trigger block is indexed at height %d, want %d",
			loc.MainChainHeight, target+1)
	}

	// (3) The shipped safety net does not fire in this band. main.go's post-rebuild
	// assertion refuses only when a RESTORED checkpoint sits at or above the target;
	// below it the condition is false and pristine main.go went on to start the node.
	if mh := chain.CkpManager.MaxHeight(); mh >= target {
		t.Fatalf("harness broken: the silent band needs the highest restored "+
			"checkpoint (%d) BELOW the target (%d)", mh, target)
	}

	// (4) THE FIX. "Applied" is a statement about bytes on disk, so it catches
	// exactly the state (2) describes, on a node whose in-RAM tip is far above the
	// target -- which is why it cannot be the tautology it replaced.
	appliedErr := chain.VerifyForcedRollbackApplied()
	if appliedErr == nil {
		t.Fatal("PRISTINE BEHAVIOUR REPRODUCED: a node that declined the rewind and " +
			"still holds the trigger block on its main chain was allowed to boot")
	}
	if !errors.Is(appliedErr, blockchain.ErrForcedRollbackNotApplied) {
		t.Fatalf("wrong sentinel: %v", appliedErr)
	}
	for _, want := range []string{"refusing to start", "DECLINED", "ela-cli rollback --height"} {
		if !strings.Contains(appliedErr.Error(), want) {
			t.Fatalf("the refusal must be unambiguous and actionable; %q missing from: %v",
				want, appliedErr)
		}
	}
}

// TestB1AppliedIsNotTheArmedFlag pins the separation on the HAPPY path: after a
// rewind that really ran, the trigger block is gone from every persisted index --
// which is what makes VerifyForcedRollbackApplied a post-condition rather than a
// restatement of the rewind loop's own exit condition.
func TestB1AppliedIsNotTheArmedFlag(t *testing.T) {
	const target = uint32(3)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+6)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	armed, err := chain.ForcedRollbackArmed()
	if err != nil || !armed {
		t.Fatalf("harness broken: armed=%v err=%v", armed, err)
	}
	before := b1b5Locate(t, chain)
	if !before.OnMainChain || !before.HeaderRow || !before.InBlockStore {
		t.Fatalf("harness broken: the trigger must start out fully present, got %s",
			before.String())
	}
	if !before.Hash.IsEqual(hashes[target+1]) {
		t.Fatalf("the located trigger %s is not the block at target+1 %s",
			before.Hash.String(), hashes[target+1].String())
	}

	if e := chain.PreflightForcedRollback(); e != nil {
		t.Fatalf("pre-flight must pass on a healthy store: %v", e)
	}
	if e := chain.ForceRollback(nil); e != nil {
		t.Fatalf("ForceRollback: %v", e)
	}
	if e := chain.VerifyForcedRollbackApplied(); e != nil {
		t.Fatalf("a completed rewind must verify as applied: %v", e)
	}
	if after := b1b5Locate(t, chain); after.Present() {
		t.Fatalf("the rewind reported success but the trigger block survives: %s",
			after.String())
	}
}

// TestB1ResidueOnlyTriggerIsPurgedNotFatal pins the OTHER severity. A node that
// rolled back correctly under a binary that did not purge the raw block store still
// SERVES the exploit block by hash (residue #2, PROVEN live). That is repairable, so
// it must be purged and the node must start; refusing here would brick the
// already-recovered cohort for a condition a targeted delete fixes.
func TestB1ResidueOnlyTriggerIsPurgedNotFatal(t *testing.T) {
	const target = uint32(3)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+4)
	trigger := hashes[target+1]

	chain, store := t1Open(t, dir, params, nil, nil)
	raw := b1b5ReadRaw(t, chain, trigger)
	if e := chain.ForceRollback(nil); e != nil {
		t1Close(store)
		t.Fatalf("ForceRollback: %v", e)
	}
	// Put the raw by-hash entry back, and nothing else: the main chain stays
	// consistent, but the node would serve the discarded block by hash again.
	b1b5RestoreRaw(t, chain, trigger, raw)
	loc := b1b5Locate(t, chain)
	if !loc.InBlockStore || loc.OnMainChain {
		t1Close(store)
		t.Fatalf("harness broken: want raw-store-only residue, got %s", loc.String())
	}

	if e := chain.VerifyForcedRollbackApplied(); e != nil {
		t1Close(store)
		t.Fatalf("retention residue must be purged, not fatal: %v", e)
	}
	if after := b1b5Locate(t, chain); after.Present() {
		t1Close(store)
		t.Fatalf("the residual trigger entry survived the purge: %s", after.String())
	}
	t1Close(store)
}

// TestB5PreflightRefusesAStoreAnInterruptedRollbackDamaged is the primary B5 proof.
//
// The store is the one an earlier interrupted rollback under the SHIPPED ordering
// leaves: the block-header index rows above the target are gone, while the
// main-chain index and the raw store still describe those blocks. The node is still
// armed, because the eaten rows sit above the one the arming predicate reads.
//
// FAILS ON PRISTINE: the same store is run through the pristine sequence (no
// pre-flight) in the sibling subtest, where ForceRollback dies part-way through on
// an internal index assertion that carries no sentinel and no remedy -- the exact
// "fails closed but opaquely" outcome the rehearsal recorded for a node interrupted
// once under the shipped ordering and then upgraded.
func TestB5PreflightRefusesAStoreAnInterruptedRollbackDamaged(t *testing.T) {
	const target = uint32(2)
	const tip = uint32(7)
	// Heights 6 and 7 lose their header rows; 3..5 keep theirs, so the node reloads
	// with tip 5 and stays armed on the block at target+1 == 3.
	const eatFrom, eatTo = uint32(6), uint32(7)

	build := func(t *testing.T) (string, *config.Configuration) {
		t.Helper()
		dir := t.TempDir()
		params := t1Params(target)
		hashes := t1BuildChain(t, dir, params, tip)
		t1EatHeaderRows(t, dir, params, hashes, eatFrom, eatTo)
		return dir, params
	}

	t.Run("fixed-preflight-refuses-with-a-remedy", func(t *testing.T) {
		dir, params := build(t)
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)

		if got := chain.GetHeight(); got != eatFrom-1 {
			t.Fatalf("harness broken: reloaded tip %d, want %d", got, eatFrom-1)
		}
		armed, err := chain.ForcedRollbackArmed()
		if err != nil || !armed {
			t.Fatalf("harness broken: the damaged node must still be armed, armed=%v err=%v",
				armed, err)
		}

		// Snapshot the store so the pre-flight can be shown to be READ-ONLY: its whole
		// value is that it reports before anything destructive runs.
		tipBefore := chain.GetHeight()
		locBefore := b1b5Locate(t, chain)

		e := chain.PreflightForcedRollback()
		if e == nil {
			t.Fatal("PRISTINE BEHAVIOUR REPRODUCED: the armed path accepted a store " +
				"carrying main-chain records the rewind can never reach")
		}
		if !errors.Is(e, blockchain.ErrForcedRollbackStoreDamaged) {
			t.Fatalf("wrong sentinel: %v", e)
		}
		// It must name the damage AND a remedy that is not a no-op.
		for _, want := range []string{"can never visit them", "Remedy:", "resync"} {
			if !strings.Contains(e.Error(), want) {
				t.Fatalf("the diagnosis must be specific and actionable; %q missing from: %v",
					want, e)
			}
		}
		// And it must NOT send the operator to purgeresidue, which removes retention
		// residue only: here it would delete the evidence while leaving the
		// un-reverted UTXO/derived state in place.
		if strings.Contains(e.Error(), "purgeresidue") {
			t.Fatalf("purgeresidue does not repair this state and must not be offered: %v", e)
		}
		// Read-only: nothing was touched.
		if got := chain.GetHeight(); got != tipBefore {
			t.Fatalf("the pre-flight moved the tip %d -> %d; it must be read-only",
				tipBefore, got)
		}
		if after := b1b5Locate(t, chain); after.String() != locBefore.String() {
			t.Fatalf("the pre-flight changed the store: %s -> %s",
				locBefore.String(), after.String())
		}
	})

	t.Run("pristine-sequence-fails-opaquely", func(t *testing.T) {
		dir, params := build(t)
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)

		// The pristine boot path: armed -> straight into ForceRollback, no scan.
		e := chain.ForceRollback(nil)
		if e == nil {
			t.Fatal("MEASUREMENT CHANGED: pristine ForceRollback now SUCCEEDS on a " +
				"store whose main chain runs past what the rewind can reach, which " +
				"would be worse, not better -- the unreachable blocks' rollback " +
				"transactions still never ran")
		}
		// MEASURED (canonical 4667fdf): an internal transaction-index assertion, part
		// way through the rewind. This is the whole of B5 -- the node fails closed,
		// which is right, but the operator gets no classification and no remedy.
		if errors.Is(e, blockchain.ErrForcedRollbackStoreDamaged) {
			t.Fatalf("this subtest models the UNGUARDED path; a classified error here "+
				"means the pre-flight leaked into ForceRollback: %v", e)
		}
		for _, mustNotContain := range []string{"Remedy:", "resync", "pre-rollback backup"} {
			if strings.Contains(e.Error(), mustNotContain) {
				t.Fatalf("MEASUREMENT CHANGED: the unguarded failure now carries %q, so "+
					"the pre-flight is no longer the only thing supplying a remedy. "+
					"Re-derive the finding before relaxing this test: %v", mustNotContain, e)
			}
		}
		if !strings.Contains(e.Error(), "assertion failed") {
			t.Logf("NOTE: the opaque failure text changed to: %v", e)
		}
	})
}

// TestB5PreflightPassesHealthyAndUnconfiguredStores is the false-positive guard. A
// pre-flight that refuses a healthy store is a restart-day outage, so both the
// ordinary armed node and a node on a network without forced rollback must sail
// through.
func TestB5PreflightPassesHealthyAndUnconfiguredStores(t *testing.T) {
	t.Run("healthy-armed-node", func(t *testing.T) {
		const target = uint32(3)
		dir := t.TempDir()
		params := t1Params(target)
		t1BuildChain(t, dir, params, target+5)
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		if e := chain.PreflightForcedRollback(); e != nil {
			t.Fatalf("healthy armed store must pass the pre-flight: %v", e)
		}
	})

	t.Run("forced-rollback-not-configured", func(t *testing.T) {
		const target = uint32(3)
		dir := t.TempDir()
		params := t1Params(target)
		t1BuildChain(t, dir, params, target+5)
		// Disarm exactly as a non-incident network is configured.
		params.ForcedRollbackTrigger = ""
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		if e := chain.PreflightForcedRollback(); e != nil {
			t.Fatalf("an unconfigured network must not pay for, or fail, the scan: %v", e)
		}
		if e := chain.VerifyForcedRollbackApplied(); e != nil {
			t.Fatalf("an unconfigured network must not be asserted against: %v", e)
		}
		if loc, err := chain.LocateForcedRollbackTrigger(); err != nil || loc != nil {
			t.Fatalf("unconfigured probe must be a no-op, got loc=%v err=%v", loc, err)
		}
	})
}
