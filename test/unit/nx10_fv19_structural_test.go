// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-10 / FV-08 + FV-19 — STRUCTURAL layer.
//
// Two different rots are being prevented here, and neither is catchable behaviourally:
//
//  1. MEMPOOL/BLOCK SLOT PARITY (NX-10/FV-08 hardening item). The block-level
//     identity-conflict guards are a MIRROR of the mempool's conflict slots. That mirror
//     was hand-maintained, and that is exactly how it came to cover two of the five members
//     of one slot and none of the two members of another while reading as done in the
//     tracker. This test parses BOTH sides — mempool/conflictmanager.go for the slot
//     membership, blockchain/blockvalidator.go for the block-level case arms — and fails if
//     a mempool slot member has no block-level arm and is not on an explicit, reasoned
//     exception list. Add a sixth transaction type to slotDPoSNodePublicKey and this test
//     names it.
//
//  2. THE DEAD-GUARD CLASS (FV-19). The F-031 LockTime pin sat in
//     CoinBaseTransaction.SpecialContextCheck, which nothing on the block-connect path
//     calls, and was "verified" by a test that called that method directly. The pin now
//     lives in blockchain.checkCoinbaseLockTimePin. This test fails if a LockTime rule is
//     put back into the coinbase's dead region — the first step of re-creating the defect,
//     and the step a reviewer would wave through.
package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. mempool slot membership <-> block-level case arms
// ---------------------------------------------------------------------------

// identitySlots are the mempool conflict slots that key on a DPoS/CR IDENTITY (public key,
// nickname, council DID). They are the slots NX-10/FV-08 is about. The stake / withdraw /
// proposal slots are mirrored by other findings and are deliberately out of this test's
// scope rather than silently asserted.
//
// The membership recorded here is what mempool/conflictmanager.go says TODAY. It is not a
// wish list: the test reads the real source and fails on ANY difference in either
// direction, so a slot that gains or loses a member forces a decision about the block-level
// mirror instead of drifting.
var identitySlots = map[string][]string{
	"slotDPoSOwnerPublicKey":           {"RegisterProducer", "UpdateProducer", "CancelProducer", "RegisterCR"},
	"slotDPoSNodePublicKey":            {"RegisterProducer", "UpdateProducer", "ActivateProducer", "RegisterCR", "CRCouncilMemberClaimNode"},
	"slotDPoSOwnerNodePublicKeys":      {"RegisterProducer", "UpdateProducer", "CRCouncilMemberClaimNode"},
	"slotDPoSNickname":                 {"RegisterProducer", "UpdateProducer"},
	"slotCRCouncilMemberNodePublicKey": {"CRCouncilMemberClaimNode"},
	"slotCRCouncilMemberDID":           {"CRCouncilMemberClaimNode"},
}

// mirror records, for ONE mempool slot member, the exact block-level structure that
// mirrors it: the transaction type must have a `case common.<txType>:` arm in `fn` and that
// arm must reference `ident`. Asserting the IDENTIFIER, not merely the presence of a case
// arm, is what makes this test discriminating: before this batch, RegisterProducer had a
// case arm in CheckDuplicateTx (owner/node keys) while the NICKNAME slot had no block-level
// structure of any kind, and UpdateProducer had a case arm in CheckDuplicateTx while being
// absent from CheckSameBlockConflicts entirely. A case-arm-only assertion would have passed
// on the defective tree.
type mirror struct {
	slot, txType, fn, ident, note string
}

// slotMirrors is the parity inventory. Every entry was read off the two sources.
var slotMirrors = []mirror{
	// slotDPoSNodePublicKey — the five-member slot at the centre of NX-10/FV-08.
	{"slotDPoSNodePublicKey", "RegisterProducer", "CheckSameBlockConflicts", "producerCRKeys", "F-100"},
	{"slotDPoSNodePublicKey", "UpdateProducer", "CheckSameBlockConflicts", "producerCRKeys", "NX-10/FV-08: added by this batch"},
	{"slotDPoSNodePublicKey", "RegisterCR", "CheckSameBlockConflicts", "producerCRKeys", "F-100"},
	{"slotDPoSNodePublicKey", "CRCouncilMemberClaimNode", "CheckSameBlockConflicts", "producerCRKeys", "NX-10/FV-08: added by this batch (claimNodeKeys alone never met the producer keys)"},

	// slotDPoSOwnerPublicKey — CancelProducer is mirrored by the UPSTREAM, ungated guard.
	{"slotDPoSOwnerPublicKey", "RegisterProducer", "CheckSameBlockConflicts", "producerCRKeys", "F-100"},
	{"slotDPoSOwnerPublicKey", "UpdateProducer", "CheckSameBlockConflicts", "producerCRKeys", "NX-10/FV-08: added by this batch"},
	{"slotDPoSOwnerPublicKey", "RegisterCR", "CheckSameBlockConflicts", "producerCRKeys", "F-100"},
	{"slotDPoSOwnerPublicKey", "CancelProducer", "CheckDuplicateTx", "existingProducer",
		"upstream/ungated. The cross-identity pairing CancelProducer(owner=X)+RegisterCR(key=X) " +
			"is structurally unreachable: the cancel is only valid while producer X is COMMITTED, " +
			"which is exactly what makes RegisterCR's ProducerExists(X) read reject."},

	// slotDPoSOwnerNodePublicKeys — the owner<->node cross-namespace array slot.
	{"slotDPoSOwnerNodePublicKeys", "RegisterProducer", "CheckSameBlockConflicts", "dedupHexKeys", "F-100"},
	{"slotDPoSOwnerNodePublicKeys", "UpdateProducer", "CheckSameBlockConflicts", "dedupHexKeys", "NX-10/FV-08: added by this batch"},
	// NX-10b: the LAST member of the block-level producerCRKeys union that the mempool did
	// not mirror. blockvalidator.go feeds the claimed node key into producerCRKeys, which
	// already holds producer OWNER keys, so "RegisterProducer.OwnerKey == claimed node key"
	// was a BLOCK conflict and not a MEMPOOL conflict. GenerateBlock never runs
	// CheckSameBlockConflicts, so both transactions were admitted, packed, and the block
	// failed its own sanity check with nothing evicting either one: a durable halt of block
	// production reachable by one CR council seat plus one producer deposit. Joining this
	// array slot closes the drift this file was written to detect.
	{"slotDPoSOwnerNodePublicKeys", "CRCouncilMemberClaimNode", "CheckSameBlockConflicts", "producerCRKeys", "NX-10b: added by this batch"},

	// slotDPoSNickname — FV-08's genuinely new half; there was NO block-level nickname
	// structure before this batch.
	{"slotDPoSNickname", "RegisterProducer", "CheckSameBlockConflicts", "producerNicknames", "NX-10/FV-08: added by this batch"},
	{"slotDPoSNickname", "UpdateProducer", "CheckSameBlockConflicts", "producerNicknames", "NX-10/FV-08: added by this batch"},

	// The two council-member slots (F-071 / F-083), already mirrored.
	{"slotCRCouncilMemberNodePublicKey", "CRCouncilMemberClaimNode", "CheckSameBlockConflicts", "claimNodeKeys", "F-071"},
	{"slotCRCouncilMemberDID", "CRCouncilMemberClaimNode", "CheckSameBlockConflicts", "claimNodeDIDs", "F-083"},
}

// knownUncoveredAtBlockLevel records, with a reason, every identity-slot member that still
// has NO block-level mirror. It must stay SHORT and each entry must name the finding that
// owns it. An empty reason is not accepted.
var knownUncoveredAtBlockLevel = map[string]string{
	"ActivateProducer": "F-119 (REAL-OPEN, not in this batch): ActivateProducer creates no NEW " +
		"key binding — its node key must already belong to a committed producer — and the " +
		"tracker requires it to move together with the F-189/F-174/F-206/F-129 cluster " +
		"behind gate 1, not piecemeal. Adding the arm here would also reject the " +
		"legitimate same-producer pairing (UpdateProducer with an unchanged node key + " +
		"ActivateProducer), which is that finding's call to make, not this one's.",
}

// parseGoFile parses one repo-relative source file.
func parseGoFile(t *testing.T, root, rel string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, rel), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", rel, err)
	}
	return f
}

// mempoolSlotMembership extracts, from newConflictManager, each conflict slot's name and
// the transaction types registered in it.
func mempoolSlotMembership(t *testing.T, root string) map[string][]string {
	t.Helper()
	f := parseGoFile(t, root, "mempool/conflictmanager.go")

	var ctor *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "newConflictManager" {
			ctor = fd
		}
	}
	if ctor == nil {
		t.Fatal("mempool/conflictmanager.go: newConflictManager not found — the slot " +
			"inventory cannot be read, so block-level parity cannot be checked")
	}

	out := map[string][]string{}
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var name string
		for _, e := range cl.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "name" {
				if v, ok := kv.Value.(*ast.Ident); ok {
					name = v.Name
				}
			}
		}
		if name == "" {
			return true
		}
		var types []string
		ast.Inspect(cl, func(m ast.Node) bool {
			kv, ok := m.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			k, ok := kv.Key.(*ast.Ident)
			if !ok || k.Name != "Type" {
				return true
			}
			if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
				types = append(types, sel.Sel.Name)
			}
			return true
		})
		out[name] = types
		return false // this slot literal is fully consumed
	})
	return out
}

// caseArmReferences reports whether function `fn` in blockvalidator.go has a
// `case common.<txType>:` arm, and which identifiers that arm references.
func caseArmReferences(t *testing.T, root, fn, txType string) (found bool, idents map[string]struct{}) {
	t.Helper()
	f := parseGoFile(t, root, "blockchain/blockvalidator.go")
	idents = map[string]struct{}{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name.Name != fn {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			hit := false
			for _, e := range cc.List {
				if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == txType {
					hit = true
				}
			}
			if !hit {
				return true
			}
			found = true
			for _, stmt := range cc.Body {
				ast.Inspect(stmt, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok {
						idents[id.Name] = struct{}{}
					}
					return true
				})
			}
			return true
		})
	}
	return found, idents
}

// blockLevelArmedTypes is the set of transaction types that have ANY mirror entry.
func blockLevelArmedTypes() map[string]struct{} {
	out := map[string]struct{}{}
	for _, m := range slotMirrors {
		out[m.txType] = struct{}{}
	}
	return out
}

// TestMempoolIdentitySlotMembershipIsUnchanged fails if a slot gains or loses a member, so
// the parity assertion below can never be quietly satisfied by the mempool shrinking.
func TestMempoolIdentitySlotMembershipIsUnchanged(t *testing.T) {
	actual := mempoolSlotMembership(t, repoRoot(t))
	for slot, want := range identitySlots {
		got, ok := actual[slot]
		if !ok {
			t.Errorf("SLOT INVENTORY STALE: mempool slot %s no longer exists; the block-level "+
				"mirror in CheckSameBlockConflicts was written against it", slot)
			continue
		}
		sort.Strings(got)
		w := append([]string(nil), want...)
		sort.Strings(w)
		if strings.Join(got, ",") != strings.Join(w, ",") {
			t.Errorf("SLOT MEMBERSHIP CHANGED for %s:\n  mempool now: %v\n  recorded    : %v\n"+
				"Decide what the BLOCK-LEVEL mirror (blockchain.CheckSameBlockConflicts) must "+
				"do about the difference — this is exactly the drift that left a five-member "+
				"slot with two block-level arms (NX-10/FV-08).", slot, got, w)
		}
	}
}

// TestEveryIdentitySlotMemberIsMirroredOrExcused walks EVERY member of every identity slot
// as the mempool actually declares it and requires either a mirror entry or a reasoned
// exception. This is the invariant that turns hand-maintained parity into an enforced one.
func TestEveryIdentitySlotMemberIsMirroredOrExcused(t *testing.T) {
	membership := mempoolSlotMembership(t, repoRoot(t))
	have := map[string]bool{}
	for _, m := range slotMirrors {
		have[m.slot+"/"+m.txType] = true
	}
	for slot := range identitySlots {
		for _, txType := range membership[slot] {
			if have[slot+"/"+txType] {
				continue
			}
			if reason, excused := knownUncoveredAtBlockLevel[txType]; excused && strings.TrimSpace(reason) != "" {
				t.Logf("KNOWN GAP %s/%s: %s", slot, txType, reason)
				continue
			}
			t.Errorf("PARITY GAP: mempool slot %s holds %s, but no block-level mirror is "+
				"recorded for it. The mempool rejects that pairing and the block validator "+
				"does not, so a malicious block packer — which never routes anything through "+
				"a stock mempool — can pack it into one block. Add the arm and a slotMirrors "+
				"entry, or add knownUncoveredAtBlockLevel entry naming the finding that owns it.",
				slot, txType)
		}
	}
}

// TestEveryRecordedMirrorIsActuallyPresent is the discriminating half: each recorded mirror
// must exist as a case arm that references the named structure.
//
// MUTATION PROOF: delete the `case common.UpdateProducer:` arm from CheckSameBlockConflicts
// -> four entries FAIL naming UpdateProducer. Delete only the addProducerNickname calls ->
// the two slotDPoSNickname entries FAIL while everything else stays green.
func TestEveryRecordedMirrorIsActuallyPresent(t *testing.T) {
	root := repoRoot(t)
	for _, m := range slotMirrors {
		m := m
		t.Run(m.slot+"__"+m.txType, func(t *testing.T) {
			found, idents := caseArmReferences(t, root, m.fn, m.txType)
			if !found {
				t.Fatalf("PARITY GAP [%s]: %s has no `case common.%s:` arm, so mempool slot %s "+
					"is not mirrored at block level for that transaction type (%s)",
					m.note, m.fn, m.txType, m.slot, m.note)
			}
			if _, ok := idents[m.ident]; !ok {
				t.Fatalf("PARITY GAP [%s]: %s's `case common.%s:` arm no longer references %q, "+
					"so mempool slot %s is not actually mirrored — a case arm that does not "+
					"feed the shared structure enforces nothing", m.note, m.fn, m.txType, m.ident, m.slot)
			}
		})
	}
}

// TestKnownUncoveredListDoesNotRot fails once an excused member gains a mirror, so the
// exception list cannot outlive the exception.
func TestKnownUncoveredListDoesNotRot(t *testing.T) {
	armed := blockLevelArmedTypes()
	for txType, reason := range knownUncoveredAtBlockLevel {
		if _, ok := armed[txType]; ok {
			t.Errorf("EXCEPTION IS STALE: %s now has a recorded block-level mirror, so it must "+
				"be removed from knownUncoveredAtBlockLevel (recorded reason: %s)", txType, reason)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. FV-19 — no consensus rule may be re-added to the coinbase's dead region
// ---------------------------------------------------------------------------

// TestFV19CoinbaseDeadRegionCarriesNoLockTimeRule fails if CoinBaseTransaction's
// SpecialContextCheck or ContextCheck reads LockTime again.
//
// Those two methods are unreachable from block connect: SpecialContextCheck's only caller
// is ContextCheck, whose only non-test caller is BlockChain.CheckTransactionContext, and all
// four call sites of that function structurally exclude the coinbase. A guard placed there
// enforces nothing while looking enforced — the FV-19 defect exactly. The live pin is
// blockchain.checkCoinbaseLockTimePin, asserted present by the wiring inventory.
//
// MUTATION PROOF: restore the deleted `if para.BlockHeight >= ... && a.LockTime() != ...`
// block in core/transaction/coinbasetransaction.go -> this test FAILS.
func TestFV19CoinbaseDeadRegionCarriesNoLockTimeRule(t *testing.T) {
	root := repoRoot(t)
	f := parseGoFile(t, root, "core/transaction/coinbasetransaction.go")

	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if fd.Name.Name != "SpecialContextCheck" && fd.Name.Name != "ContextCheck" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "LockTime" {
				return true
			}
			t.Errorf("DEAD-GUARD REGRESSION [FV-19]: CoinBaseTransaction.%s reads LockTime "+
				"again. Nothing on the block-connect path calls that method, so the rule "+
				"would enforce nothing while reading as armed — that is the exact defect "+
				"FV-19 recorded. The live pin is blockchain.checkCoinbaseLockTimePin, "+
				"called from checkCoinbaseTransactionContext.", fd.Name.Name)
			return false
		})
	}
}
