// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- OPS2 item 3: a config typo must not be diagnosed as a broken
// database, and must never trigger a destructive repair.
//
// The forced-rollback trigger is the one value on restart day an operator types by
// hand, and the whole boot path assumes it names the block at ForcedRollbackHeight+1.
// Pristine never checks that it does.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 8e78ce3, this harness):
//
//   - a trigger naming a perfectly healthy block at some OTHER height makes
//     VerifyForcedRollbackApplied refuse with "still recorded on the MAIN CHAIN at
//     height N" and prescribe "Restore a pre-rollback backup ... or wipe the data
//     directory and resync": a destructive, hours-long remedy for a mistyped hash,
//     and one that cannot possibly fix it -- the fresh resync reads the same typo.
//   - a trigger naming a block that is only in the raw store takes the RESIDUE branch
//     instead, DELETES that block from the store, and then reports "verified -- block X
//     is absent from the main-chain index, the block-header index and the raw block
//     store": a destructive action plus a false all-clear, both from one typo.
package unit

import (
	"strings"
	"testing"
)

// ops2DestructiveRemedyPhrases are the phrases that make a diagnosis destructive.
// None may appear in the answer to a configuration error.
var ops2DestructiveRemedyPhrases = []string{
	"wipe the data directory",
	"Restore a pre-rollback backup",
}

// ops2RequireNonDestructive fails when a diagnosis prescribes destroying the store.
func ops2RequireNonDestructive(t *testing.T, msg string) {
	t.Helper()
	for _, phrase := range ops2DestructiveRemedyPhrases {
		if strings.Contains(msg, phrase) {
			t.Errorf("a mistyped trigger is answered with a DESTRUCTIVE remedy (%q).\n"+
				"full message:\n%s", phrase, msg)
		}
	}
}

// TestOps2WrongHeightTriggerIsAConfigErrorNotStoreDamage is the primary item-3 proof.
//
// FAILS ON PRISTINE at the remedy assertions: the pristine text is
// ErrForcedRollbackNotApplied + forcedRollbackRemedy, which IS the wipe-and-resync
// prescription.
func TestOps2WrongHeightTriggerIsAConfigErrorNotStoreDamage(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+3)

	// The classic fat-finger: the operator pasted the hash of a neighbouring block.
	// It is a real, healthy, main-chain block -- just not the one at target+1.
	wrong := hashes[target+3]
	params.ForcedRollbackTrigger = wrong.ReversedString()

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	// Nothing is armed, correctly: the arming predicate compares against target+1.
	armed, err := chain.ForcedRollbackArmed()
	if err != nil {
		t.Fatalf("ForcedRollbackArmed: %v", err)
	}
	if armed {
		t.Fatal("harness is wrong: a trigger at the wrong height must not arm")
	}

	verr := chain.VerifyForcedRollbackApplied()
	if verr == nil {
		t.Fatal("a trigger that names the wrong block must not be accepted silently")
	}
	msg := verr.Error()

	ops2RequireNonDestructive(t, msg)
	if !strings.Contains(strings.ToLower(msg), "configur") {
		t.Errorf("the diagnosis does not tell the operator this is a configuration "+
			"problem.\nfull message:\n%s", msg)
	}
	// The two values that disagree must both be named, or the operator cannot act.
	if !strings.Contains(msg, wrong.ReversedString()) && !strings.Contains(msg, wrong.String()) {
		t.Errorf("the message never names the configured trigger.\nfull message:\n%s", msg)
	}
	if !strings.Contains(msg, "height 8") {
		t.Errorf("the message never names the height that block really sits at.\n"+
			"full message:\n%s", msg)
	}
	if !strings.Contains(msg, "6") {
		t.Errorf("the message never names the height the trigger was expected at.\n"+
			"full message:\n%s", msg)
	}
}

// TestOps2WrongHeightTriggerDoesNotDeleteBlocks is the destructive half.
//
// A trigger naming a block that exists only in the raw store (an orphan / side block,
// or any block whose header row is gone) reaches the RESIDUE branch, which purges by
// hash on the assumption that the hash is the trigger and the trigger sits at
// target+1. On a typo that assumption is false and a real block is deleted.
//
// FAILS ON PRISTINE: the block is gone and the function returns nil.
func TestOps2WrongHeightTriggerDoesNotDeleteBlocks(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+3)
	orphan := hashes[target+3]

	// Read the bytes, roll back for real, then restore ONLY the raw entry: no
	// main-chain index, no header row. That is a stored-but-unindexed block.
	var raw []byte
	func() {
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		raw = b1b5ReadRaw(t, chain, orphan)
		if rerr := chain.ForceRollback(nil); rerr != nil {
			t.Fatalf("ForceRollback: %v", rerr)
		}
	}()

	params.ForcedRollbackTrigger = orphan.ReversedString()
	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	b1b5RestoreRaw(t, chain, orphan, raw)

	verr := chain.VerifyForcedRollbackApplied()

	if !chain.GetDB().GetFFLDB().IsBlockInStore(&orphan) {
		t.Errorf("a mistyped trigger DELETED a block from the raw store; err=%v", verr)
	}
	if verr == nil {
		t.Fatal("a mistyped trigger produced a silent all-clear")
	}
	ops2RequireNonDestructive(t, verr.Error())
	if !strings.Contains(strings.ToLower(verr.Error()), "configur") {
		t.Errorf("the diagnosis does not name the real problem.\nfull message:\n%s",
			verr.Error())
	}
}

// TestOps2CorrectTriggerStillDiagnosesRealStoreDamage is the negative control: the
// item-3 fix must not turn a REAL un-applied rollback into a shrug. With the trigger
// pointing where it should, a node still holding that block main-chain indexed above
// the target must still refuse, still with the destructive-but-correct remedy.
func TestOps2CorrectTriggerStillDiagnosesRealStoreDamage(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	verr := chain.VerifyForcedRollbackApplied()
	if verr == nil {
		t.Fatal("a node still holding the trigger block on the main chain must refuse")
	}
	if !strings.Contains(verr.Error(), "MAIN CHAIN") {
		t.Errorf("the real diagnosis was weakened: %v", verr)
	}
	if !strings.Contains(verr.Error(), "wipe the data directory") {
		t.Errorf("the real, correct destructive remedy was lost: %v", verr)
	}
}

// TestOps2WrongHeightTriggerWithNoBodyIsStillAConfigError closes the one shape the
// two tests above cannot reach: a trigger naming a main-chain block whose BODY is no
// longer in the store.
//
// It matters because it is the only shape in which the main-chain index is the ONLY
// source of the trigger's real height -- with the body present the store's own header
// answers the same question. Without that source the boot falls through to the
// un-applied-rollback diagnosis and prescribes wipe-and-resync for a typo again.
func TestOps2WrongHeightTriggerWithNoBodyIsStillAConfigError(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+3)

	// A healthy main-chain block well BELOW the target, so nothing about it is
	// residue -- it is simply not the block the rollback is about.
	wrong := hashes[2]
	params.ForcedRollbackTrigger = wrong.ReversedString()

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	if err := chain.GetDB().GetFFLDB().DeleteBlockFromStore(wrong); err != nil {
		t.Fatalf("remove the block body: %v", err)
	}

	verr := chain.VerifyForcedRollbackApplied()
	if verr == nil {
		t.Fatal("a trigger that names the wrong block must not be accepted silently")
	}
	ops2RequireNonDestructive(t, verr.Error())
	if !strings.Contains(strings.ToLower(verr.Error()), "configur") {
		t.Errorf("the diagnosis does not tell the operator this is a configuration "+
			"problem.\nfull message:\n%s", verr.Error())
	}
	if !strings.Contains(verr.Error(), "height 2") {
		t.Errorf("the message never names the height that block really sits at.\n"+
			"full message:\n%s", verr.Error())
	}
}
