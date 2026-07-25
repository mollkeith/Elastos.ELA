# Changelog

All notable changes to Elastos.ELA are recorded here.

This file covers the 112 commits `d8488bf..HEAD` that make up **v1.0.0**.

---

## v1.0.0

**Previous released version: v0.9.9.6.** A `v0.9.9.7` source lineage exists —
the root commit below names it — but it was never released, so v1.0.0 is the
first shipped release since v0.9.9.6. (No `v0.9.9.7` tag is present in this
repository.) This
repository's root commit `d8488bf` is a squashed snapshot ("ELA v0.9.9.7 + all
our fixes + battle/exploit tests"), so the entries below are the delta against
**that snapshot**, not against released v0.9.9.6. See
`RELEASE-MANIFEST.md` — the v0.9.9.6 delta is an **OPEN / BLOCKED** manifest
field.

Per-version release notes for every earlier version live in
`docs/release-notes/`. That series stops at `release-notes-0.9.9.5.md`: this
tree carries **no** release note for 0.9.9.6 or 0.9.9.7. This file is the
changelog from v1.0.0 onward.

### The two height gates — and only two

Every acceptance-changing rule in this release activates at one of exactly two
coordinated mainnet heights. There is no third, and none may be added.

| Gate | Constant | Mainnet value | Introduced |
|---|---|---|---|
| **Gate 1** | `StrictMoneyRangeHeight` | **2 260 451** | inherited from the `d8488bf` snapshot |
| **Gate 2** | `RevisedDPoSRewardHeight` | **2 265 000** | **new in v1.0.0** (`e646a5d`, value set in `80378ab`) |

* **Gate 1 = `ForcedRollbackHeight + 1`.** The coordinated recovery rewinds the
  chain to **2 260 450** and restarts on 2 260 451, so gate 1 arms on the first
  block of the restarted chain.
* **Gate 2 = 2 265 000**, a fresh height about 4 405 blocks past the frozen tip
  2 260 595 (~6 days at 120 s). The Elastos core engineers directed that DPoS
  **reward-rule** changes must not ride the incident gate, so the two reward
  fixes (`F-212` empty-slot double-count, `F-011/086` ELA-only arbiter reward
  basis) wait for the rolled-back fleet to converge first. Gate 2 has exactly
  three production users: `blockchain/blockvalidator.go` and the V2/V3 arms of
  `dpos/state/arbitrators.go`.
* **Retained history at or below 2 260 450 is unaffected.** Every gated rule is
  a no-op below its gate, and every ungated change in this release is either
  crash-hardening (a panic was never an accepted block), reorg/rollback-only
  (those closures never run during linear replay), node-local retention,
  transport, tooling or configuration. The evidence is per fix — full-chain
  censuses, fail-on-pristine tests and mutation batteries, recorded in the
  individual commits and summarised below. **A single independent replay of
  0..2 260 450 on the shipped binary, compared against the frozen store, has
  not been performed** and is an `OPEN` item in `RELEASE-MANIFEST.md`.
* Gate 2's value **must be confirmed by the core engineers before deployment**
  and must be identical fleet-wide (`80378ab`).

### Contents

1. [Recovery machinery](#1-recovery-machinery)
2. [Theft, mint and reward-accounting classes](#2-theft-mint-and-reward-accounting-classes)
3. [Consensus safety and reorg revert symmetry](#3-consensus-safety-and-reorg-revert-symmetry)
4. [Authorization bypasses](#4-authorization-bypasses)
5. [RevertToPOW, confirm and illegal-evidence integrity](#5-reverttopow-confirm-and-illegal-evidence-integrity)
6. [DoS, crash and resource hardening](#6-dos-crash-and-resource-hardening)
7. [Durability and state growth](#7-durability-and-state-growth)
8. [Configuration and startup safety](#8-configuration-and-startup-safety)
9. [Cryptography and key material](#9-cryptography-and-key-material)
10. [Build, tooling and test infrastructure](#10-build-tooling-and-test-infrastructure)
11. [Documentation and corrected in-tree claims](#11-documentation-and-corrected-in-tree-claims)
12. [Release metadata](#12-release-metadata)

---

## 1. Recovery machinery

The forced rollback is how the fleet leaves the exploit chain. These commits
make it crash-atomic, make its own claims about disk true, and stop a node that
did **not** complete it from quietly joining the recovered network.

* **`ca0288e`** — Purge discarded blocks from the raw block store on forced
  rollback. **Was:** `ForceRollback` removed the header index, the height
  indexes and the tx-index siblings, but never the by-hash location entry in
  ffldb bucket `ffldb-blockidx` — the single chokepoint every by-hash serve path
  reads. A rolled-back node therefore kept **serving the discarded blocks by
  hash forever**, including the exploit block, over RPC `getblock` and P2P
  `getdata`. **Operator:** a rolled-back node no longer hands the exploit chain
  back to peers. The purge runs after `RollbackBlock` (running it earlier makes
  the rollback itself fail). Ungated; flat-file bytes are left orphaned by
  design. **Note for keystone comparisons:** bucket `0x00000001` now
  legitimately differs from an unpurged baseline by exactly the discarded keys.

* **`733d3ee`** — Offline residue cleaner for nodes that already rolled back.
  **Was:** `ForceRollback` is idempotent, so a node that rewound on the earlier,
  non-purging code would never revisit the residue. **Operator:** new
  `ela-cli purgeresidue` (node stopped). It deletes a raw-store entry only when
  it is both off the retained main chain **and** above the rollback target, is
  idempotent, and refuses on networks where forced rollback is disabled.

* **`5ab8614`** — Same purge on the **manual** `ela-cli rollback` path, which
  carried the identical residue.

* **`a1fe3d9`** — Sweep above-target **orphan** blocks. **Was:** the in-line
  purge walked only the accepted main chain, so an above-target side/orphan
  block that was stored but never joined the best chain survived. The real
  mainnet store has exactly one (`c34b71f2…`, header height 2 260 595) and a
  purged node still served it. **Operator:** `ForceRollback` alone now reaches
  clean-forward-sync parity; measured residue above target went 1 → 0.

* **`a12eb91`** — Make the forced rollback crash-atomic. **Was:** the per-block
  rewind ran three transactions in the order `DBRemoveBlockNode` →
  `RollbackBlock` → `DBRemoveBlockFromStore`; the first destroys the header row
  the block index is rebuilt from at startup, which drives both the arming
  predicate and the rewind bound. Measured on this tree: with the middle step
  made to fail, a node **ratcheted 6→5→4→3→2 across four restarts** and then
  booted "recovered" with every discarded block still main-chain indexed, while
  the residue cleaner purged 0 of 4. **Operator:** the order is now
  `RollbackBlock` → `DBRemoveBlockFromStore` → remove header row, so the header
  row is the durable resume marker and an interrupted rewind is re-attempted
  exactly once per block on the next boot. Also: the residue guard no longer
  misclassifies interrupted-rollback residue as "retained", the cleaner refuses
  to run when the retained main chain extends above the target, ~20 progress
  lines with elapsed time replace ~2, and interrupts are handled on block
  boundaries.

* **`6ee9e5d`** — Separate **ARMED** from **APPLIED** on the boot path.
  **Was:** `forcedRollbackFired` only meant "this node holds the chain the
  rollback targets", and the boot path read it as "the rollback happened".
  Measured in a 48-node rehearsal: a capacity-exceeded rewind was **declined
  48/48**, then 48/48 refused to start — 0/48 alive. Worse silently: when the
  restored checkpoint lands below the target the old assertion *passes* and the
  node comes up **un-rolled-back on the exploit chain**, from an on-duty arbiter
  seat. **Operator:** every boot now probes the persisted store for the trigger
  block in all three indexes and refuses to start if it is still main-chain
  indexed; retention-only residue is purged and the node starts. The
  capacity sentinel is now **fatal** — a node that cannot complete the rollback
  must not join the recovered network; the remedies are in the error text. A
  read-only pre-flight (`PreflightForcedRollback`) refuses, with a remedy,
  before anything destructive when the store is damaged.

* **`faf868e`** — Make the rollback's durability claims true. **Was:** ffldb
  answers reads through a 20 MiB / 300 s in-memory cache, so `ForceRollback`
  logged "persisted store verified clean" while describing the **write cache**.
  Measured: a copy of the data directory taken the instant that line was printed
  still held all four rewound blocks main-chain indexed, with best-state at the
  pre-rollback tip. An unclean exit inside the flush window discarded the whole
  rewind — and an operator who had read the completion line and disarmed the
  trigger then restarted onto the **pre-rollback chain** with nothing recording
  it. **Operator:** the census now flushes before counting, the rewind flushes
  after clearing its marker, the in-progress marker itself is flushed so it
  survives a crash, and a new un-gated boot check refuses to start a node that
  is not configured to finish a rewind its own marker says it started. New
  `database.DB.FlushCache()`. Limit stated in-tree: it can only refuse on
  evidence this binary wrote.

* **`21098e0`** — `--datadir` default shadowed the configured `DataDir`.
  **Was:** `cmdcom.DataDirFlag` is declared with `Value: config.DataDir`, so
  `c.String("datadir")` is never empty and the flag default always won.
  Measured with the real `ela-cli`: the rollback ran against `./elastos/data`
  under the CWD, created it, left the configured store untouched, and printed
  "Current height of blockchain is 0" — which on restart day reads as a data
  problem, or as a completed rollback. **Operator:** both offline commands now
  use `c.IsSet("datadir")`; an unset flag honours `config.json`. (`--conf`
  remains inert — `config.ConfigFile` is a const — so run the commands from the
  node's working directory.)

* Related operator-facing fix, landed in `6ee9e5d` (**FV-18**): `ela-cli
  rollback 2260450` — the **positional** form both remedy strings printed — hit
  `if c.NumFlags() == 0 { ShowSubcommandHelp; return nil }`, printed help and
  **exited 0** without touching the store, so a runbook step checking the exit
  status recorded success for an operation that never happened. `--height` is
  now required and its absence exits non-zero.

---

## 2. Theft, mint and reward-accounting classes

Per the standing rule, every inflation- or mint-class claim here was proven
empirically or is explicitly labelled deferred.

* **`13a094a`** — **F-015, live mainnet theft (gate 1).** **Was:** the
  real-withdraw family (`CRCProposalRealWithdraw`,
  `DposV2ClaimRewardRealWithdraw`, `VotesRealWithdraw`) is exempt from
  `RunPrograms`, so the *only* authorization is that inputs come from the
  treasury — and `SpecialContextCheck` never bound input `ProgramHash` to the
  treasury at all. An attacker funded a real-withdraw from a **victim UTXO**
  (empty programs, no signature) and pocketed the unbound change output.
  **Operator:** every input and the Votes/DPoSV2 change output are now bound to
  the correct per-type treasury. Honest withdrawals draw from and return to the
  treasury, so nothing legitimate is rejected. Proven on-chain against the live
  rehearsal chain in `9d2be09`. `F-218` was **refuted** in the same commit (the
  proposed bind would have rejected every legitimate cross-chain withdraw).

* **`9777985`** — **F-011/086, coinbase over-issuance (re-gated to gate 2 in
  `e646a5d`).** **Was:** the DPoS arbiter coinbase leg was validated against a
  reward computed on an **all-asset** fee basis while the CR and miner legs used
  the ELA-filtered basis. A producer spending a self-issued non-ELA UTXO worth V
  could hand-craft a coinbase that passed all three checks and minted
  `ceil(0.35·V)` of unbacked ELA, repeatable per block. **Operator:** at and
  above gate 2 the arbiter reward derives from the ELA-filtered fee, the same
  basis as the other legs. For any all-ELA block the two bases are identical, so
  no honest block changes. **Classified DORMANT by measurement** (`df066d4`): a
  full scan of all 2 260 597 retained blocks found **zero** outputs with a
  non-ELA asset id, ever, and `F-056` bans `RegisterAsset` at and above gate 1,
  so the precondition is structurally unreachable. Kept as defence in depth.
  Empirical wedge proof in `b4cea44`.

* **`e646a5d`** — **F-212, empty DPoS arbiter slot reward paid twice (gate
  2).** **Was:** the empty-slot loop added `individualBlockConfirmReward` to the
  burned total but not to `realDPOSReward`, so the caller's
  `change = reward - realDPOSReward` was over-stated and the same reward was
  emitted twice — once burned, once spendable (~16.67 ELA per round for two
  empty slots on a 100 ELA round). **Operator:** accounted correctly at and
  above gate 2. Realized exposure before then is a **measured zero** (full
  mainnet scan). This commit also introduces gate 2 itself and records the core
  engineers' answers (F-056, F-057, ELA-only-by-design, rollback-is-masking,
  trigger byte-order).

* **`80378ab`** — Gate 2 given its value: `MainNetRevisedDPoSRewardHeight =
  2265000`. **Was:** `math.MaxUint32`, which shipped F-212, F-032 and F-011/086
  as dead code. **Operator:** this single value must be identical fleet-wide and
  is pending core-engineer confirmation.

* **`bc3fc36`** — **B4: same-block double-pay (gate 1).** **Was:** the mempool
  conflict manager rejects two conflicting stake/reward/withdraw/tracking
  transactions, but block validation never mirrored those slots — so an on-duty
  producer could bypass its own mempool and pack both into **one block**, giving
  a double `ReturnVotes`/`ClaimReward` payout (F-028), a double `RealWithdraw`
  (F-066), a double unused-budget return (F-067) or cloned renewal votes
  (F-078). **Operator:** new `CheckSameBlockConflicts` in `CheckBlockSanity`
  mirrors the mempool slots at block level on the exact conflict identity, so
  two *different* identities of the same type in one block stay legal. `F-088`
  (a claimed StakePool drain) was **refuted** empirically.

* **`6c2a3ac`** — Four more mirrored slots (gate 1): `F-047` duplicate
  `CRCProposalWithdraw` on one proposal hash (double CRExpenses payout),
  `F-068` two `ReturnDepositCoin` with disjoint UTXOs both refunding against the
  same committed balance (over-refund of a forfeited bond), `F-071` two council
  members claiming one DPoS node key, `F-072` duplicate proposal draft hash.
  **Replay-safety measured:** a read-only scan of all 145 mainnet blocks in
  [2 260 451, 2 260 595] found zero occurrences of any mirrored type.

* **`2e6533b`** — Cross-chain same-block and V2 dedup gaps (gate 1 where
  acceptance-changing): `F-016` double `ReturnSideChainDepositCoin` refunding
  one sidechain deposit; `F-017` two `WithdrawFromSideChain` crediting one burn
  (the sidechain hash rides in output payloads that `CheckDuplicateTx` never
  inspects); `F-051` V2 withdraws that skipped the committed cross-block dedup
  entirely, plus a rollback processor that handled only V0/V1 and could brick a
  reorged V2 burn. `CRAssetsRectify` was checked as an F-015 sibling and found
  **already guarded**.

* **`92b4906`** — **F-104 / F-118 NFTDestroy id dedup (gate 1).** **Was:** a
  repeated NFT id inside one payload, and two same-block NFTDestroy transactions
  sharing an id, both double-applied the destroy (rights and reward).
  **Operator:** duplicate ids rejected within a transaction and across a block.
  *Live sidechain proof of this pair remains deferred — see Known limits.*

* **`dcedb58`** — **F-073 cross-key reward misallocation (gate 1).** Corrects
  our own earlier claim that F-104/F-118 closed F-073 — they do not; they close
  a same-id collision, while the hole is on the reward **key** with distinct
  ids. Proven empirically by driving the real state machine through
  apply/commit/rollback: 500 sela misallocated to an aliased owner after a
  reorg. **Operator:** an NFTDestroy whose owner stake addresses intersect the
  stake-address set derived from its own ids is rejected at and above gate 1; a
  legitimate new owner is a user stake address and is never affected.

* **`b50d37e` (FV-09)** — The F-073 guard was **intra-transaction only** and
  split across two same-block transactions. Closed at block scope (gate 1) plus
  a rollback-closure correction that measures the credit inside the forward
  closure so apply/revert are exact inverses. Accounting defect — **no mint, no
  supply inflation.**

* **`298b9f8`** — **F-013, frozen-address rule unenforced on the coinbase (gate
  1).** **Was:** the "no sends **to** a frozen address" half of the quarantine
  ran only for block transactions `[1:]`; the coinbase has its own validator and
  its merge-miner output is producer-chosen and unconstrained, so a coinbase
  could pay the quarantined CrossChain-UTXO exploit intermediate address
  straight from the block reward with no validator objecting. **Operator:** any
  coinbase output paying a configured frozen address is rejected at and above
  gate 1.

* **`b942543` / `dbfe812` (FV-19)** — **F-031, immature coinbase spend (gate
  1).** **Was:** the 100-block coinbase maturity window is derived from the
  coinbase's **own** `LockTime`, which nothing validated, so an elected producer
  could set it to 0 (or to a future value and underflow `uint32`) and spend the
  reward before maturity, defeating reorg safety. `dbfe812` then proved the
  shipped pin **inert** — it lived in `CoinBaseTransaction.SpecialContextCheck`,
  which nothing on the block-connect path calls — moved it to the live validator
  and deleted the dead copy, and closed the `checkInvalidUTXO` underflow behind
  the same gate. **Measured:** across the retained chain, coinbases with
  `LockTime != height`: **zero**.

* **`3187a25`** — **F-056 empirical exploit proof (test-only).** Drives the real
  unspent index against a real ffldb: a UTXO spent by a `RegisterAsset`
  transaction is never retired, so a later transfer re-spends it — a real double
  spend, reproduced 6×. The fix (banning `RegisterAsset` at and above gate 1)
  was already shipped.

* **`dad1f68`** — **F-089 coinbase remint proof (test-only).** Two identical
  coinbases resurrect a spent output through the real unspent index. The
  upstream `checkCoinbaseBIP30` guard rejects the duplicate-coinbase block
  before connect; this proves the mechanism it prevents.

* **`b4cea44`**, **`df066d4`** — Empirical proof and DORMANT classification of
  the non-ELA fee wedge (test-only; see `9777985`).

* **`3d3ab1c`** — Closes two evidence gaps: proves the **BIP30 duplicate-txid
  oracle itself** against a real ffldb-backed store, and drives the real
  Arbiters capture → cold restart → recover path for F-096.

* **`5ee6adb`** — **F-100 / F-083 (gate 1).** Two same-block registrations
  sharing a public key — producer↔producer or producer↔CR — bound one key to two
  identities; and a second same-member council claim-node touched one member
  twice, which the History contract forbids.

* **`dbfe812` (NX-10/FV-08)** — Completes that parity (gate 1): the mempool
  holds **five** transaction types in one node-key slot and **two** in the
  nickname slot; the block mirror had two of five and **no nickname handling at
  all**. Nicknames matter because the state keyframe stores them as a **set** —
  two same-block bindings insert idempotently while the two reverts each delete
  once, so one cancel or one reorg frees a nickname a live producer still holds.
  **Measured:** the production check with its gate forced to 0 rejects **zero**
  of the 2 260 597 retained blocks; positive control: 1 155 real historical
  producer transactions replanted with a synthetic same-block partner →
  2 310/2 310 rejected here, 0/2 310 on canonical.

* **`8a56f10` (NX-04, gate 1)** — The CR claim-node validator never checked the
  claimed node key against the producer **owner** keyspace, so one council
  member could shadow any producer's owner identity: registration lockout,
  deposit lockout and a permanent third-party voter stake **lock** (not a mint).
  Deliberately narrower than the original report, which would have broken a
  re-elected member's legitimate re-claim.

---

## 3. Consensus safety and reorg revert symmetry

A rollback-based recovery is only sound if apply and revert are exact inverses.
Everything in this section is reorg/rollback-only and therefore **ungated**
unless stated: those closures never run during linear replay, so retained
history derives byte-identically.

* **`e376150`** — **F-093 / F-094 / F-106: make the emergency `ForceChange`
  transactional with block connect.** **Was:** `connectBlock` runs
  `PreProcessSpecialTx` *first* — before context checks, before confirm
  validation and before the block is stored — and the emergency force-change was
  bound to `block.Height-1`, which `History.RollbackTo` (strictly-greater-than)
  cannot reverse. Measured on the pristine tree: after a **rejected** block the
  node kept `forceChanged=true` and 7 arbiters where it had 5, and kept the
  processed-payload marker, which lives outside History entirely — so the same
  special transaction could never force-change again on the surviving chain. Any
  peer can feed a block that pre-processes and then fails a later check.
  **Operator:** the whole connect is bracketed by a savepoint that is committed
  on success and undone on every failure exit; `utils.History` gains
  `Savepoint`/`UndoTo`.

* **`dcacb82` → `3d2816f`** — The first F-093 attempt (bind the force-change to
  `block.Height`) was **reverted**: block H is not yet stored when
  `PreProcessSpecialTx` runs, so the binding produced a block/height mismatch.
  Recorded because the unit tests exercised only the height helper and missed
  it. Superseded by `e376150`.

* **`131edce`** — **N-001:** four DPoS-gossip callers opened the new savepoint
  and never closed it, so the next failing connect or rollback **silently
  reversed a live emergency force-change** (7→5 arbiters) — a new divergence our
  own fix introduced, remotely triggerable. **Operator:** all four now commit
  unconditionally, restoring the pre-fix permanent-gossip semantics.

* **`7ba33da`** — `Arbiters.RollbackSeekTo` did not clear a pending savepoint,
  so an uncommitted emergency change could **outlive a seek** and a later undo
  could over-pop, leaving `forceChanged=true` with the marker gone.

* **`3748b74`** — The emergency bracket was three separate lock acquisitions, so
  two brackets on different goroutines interleaved. Measured worse than
  predicted: 8 goroutines against one real Arbiters produced **14+ data races**
  and a torn arbiter set (5→2). **Operator:** a dedicated `specialTxMtx` is held
  across the bracket boundaries. `RollbackTo`/`RollbackSeekTo` deliberately do
  **not** self-acquire — the confirm-failure path reaches them while the lock is
  already held, and self-acquiring would deadlock.

* **`82dc348`** — **N-001 R2:** four more brackets on the checkpoint side (the
  startup replay, both `OnBlockSaved` sites, and reset/restore) mutate the same
  state and were left open. Startup is **not** single-threaded — the DPoS
  arbitrator starts before `InitCheckpoint`. Fail-on-pristine measured 36 data
  races with both locks reverted.

* **`17f1c09`** — **G1: an AB-BA deadlock introduced by our own commits.** Three
  sites held `specialTxMtx` across `events.Notify`, and exactly one subscriber
  dispatched inline into `LockSpecialTx`, closing the cycle. Measured: the
  package test wedged at its 30 s watchdog and `events.mtx` was then held for the
  rest of the process. **Operator:** the one inline arm now dispatches with `go`
  (matching its two siblings), and `connectBlock` splits so the block-connected
  broadcast happens outside the bracket. The full lock-order graph is recorded
  in the commit. Also reported, **not ours and not fixed**: a pre-existing
  `a.mtx ↔ s.mtx` back edge present byte-for-byte at `d8488bf`.

* **`937caf4`** — **F-041 / F-090: malleable AuxPow encoding (gate 1).**
  **Was:** `ParentHash` and the high bits of `ParMerkleIndex` are never
  validated, yet the header folds the whole AuxPow into `HashWithAux()`, whose
  tail seeds DPoSV2 committee selection — while the block's consensus identity
  excludes the AuxPow. Two encodings of one block therefore shared hash/PoW/index
  key but split the committee at **zero PoW cost**. **Operator:** non-canonical
  encodings are rejected at and above gate 1. **Census:** zero non-zero
  `ParMerkleIndex` ever; last non-canonical `ParentHash` at height 2 090 418,
  170 033 blocks below the gate.

* **`2526a6b`** — **The production side of F-041.** `pow.SolveBlock` never
  stamped `ParentHash`, so **every self-mined block** left the search with
  `ParentHash = 0x00…00` and would be rejected by the new gate — i.e. a
  self-mining node could not produce the first block of the restart, and
  `DiscreteMining` swallowed the rejection and reported success with an empty
  hash list. **Operator:** stamped from the winning nonce (a stamp taken before
  the search goes stale on the first iteration). Merge-mining via
  `submitauxblock` is unaffected.

* **`f6ea5b2`** — **T0 / NX-01: the F-032 block-validity binding is WITHDRAWN.**
  **Was:** `f2270bc` made block validity a function of
  `lastBlock.Confirm.Proposal.Sponsor` — a value nothing commits to (it rides
  outside `Block.Hash()`), which producer and validator derived by **different**
  rules, and about which honest nodes legitimately disagree after a view change.
  Armed at gate 2, ~4 400 blocks past the restart tip, that was a **permanent,
  unrecoverable consensus split**. **Operator:** the rule is removed (deleted,
  not merely unwired) and replaced by a pure diagnostic; the residual F-032
  exposure — a producer naming any current/last arbiter and redistributing a
  **conserved, non-inflationary** sponsor reward — is accepted. This commit also
  **blocks** the pending proposal to move the F-032 gate down to gate 1. Plus
  NX-05: the operator sponsors file now resolves relative paths against the node
  data directory, fails startup loudly on an unreadable/malformed file instead of
  silently loading an empty map, no longer panics on a malformed line, rejects
  negative heights and duplicates, and logs byte count/entry count/SHA-256 for
  fleet comparison.

* **`accaa11`** — **F-168:** the inactivity rollback closure hard-coded
  `workedInRound` back to `true`, so a reorg across a round boundary made a
  producer that had **not** sponsored a block look as if it had.

* **`f26ffc7`, `02e41e0`, `c01951c`** — **F-075 / F-065 and siblings.** F-075:
  the expired-NFT revert closure carried an **active, unmatched** subtraction
  from `UsedDposV2Votes`, deflating a new owner's used-vote count on reorg and
  inflating castable rights. F-065: `DepositOutputs` was written directly (no
  History wrap) in four places, so a rollback left stale entries that got baked
  into the local keyframe checkpoint — a reorged node diverges from a
  canonically synced one. `c01951c` then fixed the fix: an unconditional delete
  is **not** the inverse of a set when the key pre-existed (found by a failing
  `TestCommitee_RollbackCRCBlendTx`, git-bisected to `f26ffc7`); the value and
  its existence are now captured and restored.

* **`b6faaa5`** — **Class-E batch.** `F-064` (critical): the undo guard re-read
  a counter the forward pass had **zeroed**, so a producer stayed **stuck
  Inactive** after a reorg across the threshold. `F-215`: the undo hard-set the
  producer to `Canceled` instead of restoring the captured state. `F-180`: the
  DPoSV2 activation-height rollback restored the wrong sentinel. `F-109`:
  `RollbackTo` never pruned height-keyed snapshots above the target, and
  `SnapshotByHeight` **appends**, so a reorg left stale arbiter snapshots.
  (`F-130`, a history-capacity guard, was prototyped and **reverted** — it broke
  the silent-nil `RollbackTo` contract callers rely on.)

* **`b942543` (F-048)** — The `ChangeProposalOwner` revert captured the owner of
  the **change** proposal instead of the owner of the **target** proposal it
  actually mutates, so a reorg dropping a mismatch-owner change transaction
  restored the **wrong** owner. Governance-consistency divergence after a reorg;
  the recipient reverted correctly, so not theft.

* **`0b8b482`** — **F-181:** the forward delete from `DposV2EffectedProducers`
  was decided on a pre-block capture but the revert **re-derived** membership and
  only ever added, so a producer present before the block was silently dropped on
  reorg. `len()` of that map feeds `isDposV2Active()`.

* **`e6dc1fd`, `7be226e`** — **F-131:** `History.RollbackTo` set `height` but not
  `seekHeight`, so a later commit computed a `uint32` difference that
  **underflowed to ~4.29e9** and corrupted the seek loop. `7be226e` replaces the
  first test, which passed on pristine too, with one that exercises the real
  harm (`RollbackTo` → `SeekTo`).

* **`ceea0d9`** — **F-144:** two CR checkpoint paths bound the history-member
  lookup to a **throwaway** committee object that is discarded immediately and
  never advanced, and nothing re-registers afterwards — so the wrong binding
  persisted for the node's lifetime and post-reset lookups resolved against
  frozen state.

* **`d9a6ec6`** — **t3-state (six findings).** `FV-01` (high): nothing ever
  lowers a checkpoint height, so after a deep reset a restored checkpoint that
  was **ahead of the chain** made both the startup replay and the attach loop
  no-ops — the node ran at full block height with **empty CR/DPoS state**. New
  `DiscardStaleCheckpoints`, wired through a separate entry so the startup path
  is untouched; the reorg path now also checks and returns the rebuild error it
  used to discard. `FV-12`: the arbiter snapshot ring survived a deep reset and
  got **unioned** with the canonical replay's frames — and F-082 makes that ring
  authoritative at gate 1. `FV-05`: `RollbackSeekTo` nilled temp changes without
  running their closures, making an emergency-inactive preview permanent.
  `FV-27`: a backward seek left groups to be rolled back **twice**. `FV-11`
  (apply half at gate 1): the emergency inactive pair computed its inverse
  instead of capturing origins, so undoing a payload naming an **already
  inactive** producer promoted it to Active and back into the arbiter-eligible
  set while debiting a penalty it never paid; census found 6 such transactions in
  all history, **zero** at or above gate 1. `FV-10` (high): the CR twin of F-064
  never got F-064's capture, so a reorg left a CR member stuck inactive — out of
  the CRC set that carries the multisig quorum — with its penalty never reverted.

* **`b50d37e` (FV-06, gate 1)** — Illegal-confirm validation took its majority
  **threshold** from the *current* committee while checking **membership**
  against the evidenced-height snapshot, and let one signer set span multiple
  snapshot frames. Now one frame decides both.

* **`8e574e7`** — **F-139:** `ConsensusBlockCache.Reset` appended kept hashes to
  the **old** list instead of the new one, so the rebuilt list still carried
  every dropped block and diverged from its own map.

* **`8ebff84`** — Corrects a factually wrong in-tree rationale (`History.Append`
  **defers** apply to `Commit`; it does not run it synchronously), adds a
  contract comment at `Append`, and records that F-073's soundness rests on fix
  **interaction** with F-104/F-118, not on apply timing. Also re-pins gate 2 to
  Disabled on non-mainnet default arms for symmetry.

---

## 4. Authorization bypasses

* **`679855e` + `997c5be`** — **F-022 (gate 1):** the arbiter special-transaction
  checks validated only the multisig **code** and never verified the parameter
  signatures over the transaction, so **anyone** could forge an unsigned
  `InactiveArbitrators` / `RevertToDPOS` with all-public inputs and trigger a
  permissionless emergency force-change or consensus downgrade. `997c5be` is the
  important follow-up: the second code path gated on the **current tip** rather
  than the block height, so a fresh-from-genesis replay (tip pinned above the
  gate) would re-verify signatures on **all** historical special transactions —
  violating the fix's own replay-safety invariant and risking a bootstrap brick.
  Now threaded on block height everywhere.

* **`219de01`** — **B3: producer-transaction auth fall-throughs (gate 1).**
  `F-039` / `F-069` (live, permissionless): the payload-version dispatch
  authenticated only *defined* versions, so an **unknown** version fell through
  with **no owner proof** and cancelled or rewrote an arbitrary producer —
  identity takeover. `F-021` (live, CR-privileged): the CR activation branch
  returned "end" unconditionally, skipping the fee **and** the input-signature
  check, so above `NFTStartHeight` an activate could spend arbitrary UTXOs with
  no ownership proof (theft, not inflation). `F-025`: the multi-code cancel
  branch checked "is multisig" but not that the code equals the owner key.
  **Measured:** zero type-9/10/11 transactions above the gate in the retained
  band, so no legitimate transaction is rejected. `F-004` verified and
  **refuted** as a distinct finding.

* **`6e97c74`** — **F-049 / F-091 (gate 1).** F-049: a Standard/Deposit-prefixed
  program whose code hashed to the address but was neither Schnorr, Standard nor
  MultiSig fell through `RunPrograms` with **no signature check at all** —
  anyone-can-spend of any UTXO parked at such an address. F-091: multisig
  verification treated `m <= 0` as trivially satisfied, so an `m < 1` cross-chain
  redeem script was anyone-can-spend on freeze-off paths. Both fail closed at and
  above gate 1; this required threading the block height through `RunPrograms`
  (and deliberately **not** gating on the tip — the F-022 lesson).

* **`8ee5a55`** — **Gate-deny batch (gate 1).** `F-026`: `RegisterProducer`
  gates the Schnorr version but `UpdateProducer`/`CancelProducer` did not, so the
  Schnorr re-key path was bounded only by the general Schnorr height. `F-046`:
  `UpdateCR` inherited a no-op version check, so unknown/dormant payload versions
  bypassed the discipline `RegisterCR` enforces. `F-175`:
  `CRCProposalWithdraw` had no default case, so a v≥2 payload skipped **both**
  recipient bindings and reached only the owner-signature check — an
  unconstrained-output withdrawal.

* **`6396036`** — **F-052 (gate 1):** `NFTDestroyFromSideChain` carries a genesis
  block hash that was never checked against each NFT's recorded origin, so an
  arbiter-signed destroy could name **any** sidechain. Flagged in-code: unlike
  its sibling F-074, a mismatch is *silently* accepted, so absence from the
  re-derived band is not scan-provable — confirm absence or move to a fresh
  dormant height if any node re-derives by replay.

* **`2734a9e`** — **F-185: the aggregate-Schnorr withdraw was not dormant (gate
  1).** **Was:** `SchnorrStartHeight` was enforced in one direction only —
  nothing rejected a **V2 payload below** it — so the V2 path was dispatchable at
  **any** height even though mainnet has the feature disabled
  (`math.MaxUint32`). That path builds the group key as a **plain sum** of signer
  node keys, with no MuSig coefficients and no proof-of-possession, so an arbiter
  registering a rogue key could alone forge a full-threshold cross-chain withdraw
  naming honest arbiters without their participation. **Operator:** V2 is refused
  below `SchnorrStartHeight` and versions above V2 are default-denied; the
  accumulator inputs are crash-hardened ungated. **Census (read-only, real
  chain):** 3 295 V0 and 7 786 V1 withdraws, **zero V2 ever**, and **zero**
  Schnorr program codes chain-wide — closing this path removes no behaviour the
  chain has ever used. The aggregation math is deliberately **not** changed
  (that needs MuSig or F-189, coordinated with `Elastos.ELA.Arbiter`).

---

## 5. RevertToPOW, confirm and illegal-evidence integrity

* **`0c7d991`** — **F-098:** the `RevertToPOW` type dispatch had no default arm;
  unknown types now default-reject.

* **`50aa3c4` → `43552ef` → `ed54844`** — **F-057, the forged DPoS→POW stall.**
  **Was:** the in-block check measures "time since the previous block" from the
  block's **own header timestamp**, which its producer writes, and sanity only
  bounds a header at adjusted-time + 7 200 s. Because
  `RevertToPOWNoBlockTimeV1` (7 200 s) **equals** `MaxTimeOffsetSeconds`
  (7 200 s), a producer could post-date one header by exactly the stall window
  and force DPoS→POW with **zero elapsed time**.
  * `50aa3c4` first closed it by additionally requiring the validating node's
    own median-adjusted clock to confirm the interval.
  * `43552ef` (**FV-22**) **withdrew** that: the node clock is local wall time
    plus a median over up to 199 **peer** samples, so two honest nodes with
    identical chain state and different peer sets reach opposite accept/reject
    verdicts on the same block — a category error in an acceptance decision, and
    it armed on the first block of the recovery fork. The review's suggested
    `CalcPastMedianTime` replacement was **measured and rejected**: the median
    sits below the parent's own timestamp in 2 241 of 2 241 samples (mean
    601.5 s) and in all 30 historical RevertToPOW blocks, so it would have been
    ~600 s *more* permissive than the rule it replaced.
  * `ed54844` is the owner's decision, **option (b)**: at and above gate 1 the
    in-block branch demands `noBlockTime + MaxTimeOffsetSeconds` — more than a
    producer can manufacture, so whatever it post-dates, at least `noBlockTime`
    of **real** time must have elapsed since the parent. Deterministic and
    ancestry-only: header timestamp minus **parent** timestamp, both consensus
    data. No wall clock, no peer-dependent quantity, no new height.
  * **Measured cost, and it is real:** all 30 historical `RevertToPOW`
    transactions lie below gate 1, so **zero** retained blocks change verdict;
    but 28 of the 29 `NoBlock` rescues would have had to wait longer (min
    6 807 s, max 7 188 s). **Emergency failsafe latency goes from ~2 h to ~4 h.**
  * `43552ef` also fixed **FV-22 change 1** (ungated): the interval was measured
    from the validating node's **current tip**, not the block's own parent —
    wrong on a competing branch. Now threaded from the block path. Measured: over
    all 2 260 596 heights every block links to a stored parent, and all 29
    historical `NoBlock` transactions still pass against their own parent
    (margins +12 s to +42 040 s — note the 12 s minimum: this rule has almost no
    historical slack).

* **`43552ef` (NX-06, gate 1)** — **A confirm nobody checked.** The block path
  skips the **only** membership and quorum check on three legs: below
  `CRCOnlyDPOSHeight`, on a block carrying a `RevertToPOW`, and when the node is
  in POW mode. On those legs a confirm arriving with the block was **stored and
  served** with nothing verified but the attacker's own signature over his own
  key — and the confirm sits outside `Block.Hash()`, so the attack needs no
  hashpower and no keys. One block later the sponsor rule splits on confirm
  presence and poisoned nodes halt or partition. **The restart is expected to
  begin in POW mode, which is one of those legs.** **Operator:** at and above
  gate 1 such a block is **refused** (not nil-ed), so the honest confirm-less
  copy is still accepted afterwards. **Census, two independent methods:** zero
  confirms in any of the 30 reconstructed POW windows and zero below
  `CRCOnlyDPOSHeight`; and above it exactly 4 maximal no-confirm runs (1 299
  blocks), every one opened by a `RevertToPOW`, closing to the block
  (343 400 + 1 299 = 344 699). *Residual: still open **below** gate 1 for a node
  syncing from genesis — runbook item.*

* **`248115a`** — **Illegal-evidence batch (gate 1).** `F-029`: the signer check
  admitted a **padded** signer list (duplicates, real signers dropped) that still
  matched the vote count and stayed a subset, so a submitter could steer the
  punished intersection and **shield a colluding double-signer**; now strict set
  equality. `F-082`: the confirm sponsor and vote signers were validated against
  *every producer that ever registered* instead of the round arbiters, so
  off-duty producers could be counted toward a fabricated majority; now validated
  against the on-duty snapshot at the evidenced height. `F-030` (redone — the
  earlier fix was incomplete): the dedup key folded the **raw** header bytes,
  but the header's consensus identity excludes the whole AuxPow, so two encodings
  of one logical illegal block produced **different dedup keys** — an unbounded
  dedup bypass. Now folded onto a logical identity. **Census:** zero
  illegal-block evidence transactions in 2 260 597 blocks.

* **`2b4b662`** — **F-030 closeout (gate 1):** the cross-block fix could not see
  a second encoding **inside the same block** (committed-state reads do not see
  the block under validation, and full-transaction-hash dedup does not collapse
  re-encodings), so the illegal penalty could be applied twice. A same-block arm
  covering all five special-transaction types now uses the **same** key function
  as the read and write paths.

* **`b50d37e` (NX-08, gate 1)** — The illegal-**proposal** and illegal-**vote**
  dedup keys were still malleable: the header deserializer discards its trailing
  sentinel without asserting the buffer was consumed, so **one appended byte**
  minted a fresh key, and one genuine equivocation could mint unbounded evidence
  transactions — each adding a permanent entry serialized into every DPoS
  keyframe. Both families now fold onto the logical identity, with domain tags
  keeping the three key spaces disjoint. **Census:** 13 illegal-proposal and 269
  illegal-vote transactions in all history, **zero** at or above the gate.

---

## 6. DoS, crash and resource hardening

All ungated unless noted: a panic is never an accepted block, and a retention
ceiling on blocks that never passed context validation cannot change what is
valid. None of these changes an acceptance decision.

**Unauthenticated remote node-kill and information disclosure**

* **`09d5de4`** — **F-036: remote node-kill via REST `/api/v1/restart`.**
  Proven: two concurrent unauthenticated GETs, 5/5 runs, process exit code 2.
  Auth exists only in the JSON-RPC server; REST and WebSocket have none, and the
  route ran `Stop(); Start()` in a **bare goroutine** where the tree's `Fatal`
  does not exit — so every failure path fell through to `Serve` with a **nil**
  listener and the panic escaped net/http's per-connection recover. **Operator:**
  the route is **removed** (restart via systemd) and `Start` returns on every
  failure path. **Reachability:** the stock mainnet sample leaves REST off, but
  the config operators actually copy turns it on, so explorers, indexers, wallet
  backends and fleet tooling **were** exposed. Interim mitigation without
  upgrading: firewall 20333/20334/20335 or set `HttpRestStart`/`HttpWsStart`
  false. The finding's headline ("sensitive mining/log methods exposed") is
  **refuted** — those live only behind JSON-RPC auth. Lifting auth onto REST/WS
  is deliberately **not** shipped: it would 403 every cross-host consumer on
  upgrade.

* **`b8fdecd`** — **The node-info port served pprof.** `net/http/pprof`'s `init`
  registers on the global default mux, which the info service used with a nil
  handler — so an unauthenticated `GET /debug/pprof/cmdline` returned **the full
  process argv**, and the keystore password can be passed as `--password`.
  **Operator:** the info port now serves a private mux with only `/info`; pprof
  routes 404 there. A second pprof surface via the profiler exists but only when
  `ProfilePort != 0` (off by default).

* **`ef4cccd`** — **T1: three more unauthenticated kills.** `FV-03`: a payload
  decoder passed three wire varints straight to `make` as **capacity**,
  reachable **pre-handshake** over the tx message (the first message of a
  connection is fully decoded before it is checked to be a Version) — **40
  unauthenticated bytes kill any node.** This was a hole in our own F-012
  remediation, which capped three sibling decoders and walked past this file; the
  cap is **measured** (over all 41 922 such transactions in mainnet history the
  maxima are 12/36/0 keys, so 1024 is 28×). `NX-03`: a validator indexed
  `Inputs()[0]` of a transaction named by an attacker-controlled hash — and the
  genesis asset transaction has **zero inputs** and its hash **is** the
  compiled-in asset id, so the kill needs no chain lookup, no key, no membership
  and no valid signature, and runs on a goroutine with no recover. `NX-02`: the
  orphan pool was bounded by count (10 000) but never by **bytes** — an ~85 GiB
  ceiling, a 16 GiB node dead at ~16 GB delivered; now bounded by bytes
  (256 MiB) and count (1024), evicted oldest-first and swept from the
  block-connect path. Ban-scoring orphans is deliberately **not** shipped — it
  would penalise honest peers during the post-restart resync.

**Parse, bounds and allocation guards**

* **`bc9bacd`** — **B7 (six findings).** `F-203`: the multisig-code parser had
  only an entry-length guard, so its advanced reads sliced out of bounds —
  pre-auth, before any signature check. `F-204`: a 1-byte CR code with a crafted
  matching id reached a negative-length slice. `F-172`: an AuxPow guard counted
  **hex characters** where the read takes raw bytes. `F-173`: an
  attacker-controlled merkle height ≥ 32 overflowed a shift to 0 and **divided by
  zero**, pre-PoW. `F-012`: two payload decoders allocated from a wire varint
  before any budget check (remote OOM). `F-188`: a map **write** under a read
  lock → Go's uncatchable "concurrent map read and map write".

* **`fd200aa`** — **B8.** `F-050`: a Schnorr program with a short parameter
  panicked the copy — pre-auth, P2P-relayed. `F-034`: an empty bloom filter with
  a non-zero hash count divided by zero. `F-076`: a TOCTOU nil-deref between the
  loaded check and the match. `F-077`: the per-peer requested-transaction map was
  unbounded. `F-042` verified **already closed**.

* **`509d9ce`** — **Halt-DoS batch:** `F-133`/`F-099` two `len<2` index panics on
  multisig code; `F-132` a zero-input parent coinbase; `F-153` a missing `return`
  that passed a **nil peer** to association; `F-010` a nil check on the wrong
  value; `F-171` an empty snapshot key list indexed at `len-1`.

* **`fd63b77`** — **Finding H:** the two structurally identical siblings of
  F-099 in the block-validator copy were missed, and they **are** reachable
  pre-auth — the revert-to-DPoS check is literally a direct call from the DPoS
  gossip handler, with no sanity check, so a gossiped message with empty programs
  or a <2-byte code panics the receiving **CRC arbiter**.

* **`0c75385`** — **F-058:** the next-arbiters comparison length-checked only one
  of two lists and indexed the attacker-supplied one.

* **`1b0c772`** — **F-001:** an unguarded `int64 +=` could wrap a huge
  cross-chain transfer negative and misclassify it as *small* — confirmed
  reachable in the mempool wherever gate 1 is disabled. Mempool-routing only, no
  mint/theft/consensus effect. `F-038`, `F-063`, `F-079` verified **already
  closed**.

* **`b439675`** — **Deserialize errors:** `F-053` a ~10-byte fragment declaring
  16 MB forced a 16 MB allocation that was then discarded on error — reads are
  now chunked above a 64 KB pre-allocation cap, byte- and error-identical
  otherwise (the 16 MB ceiling is deliberately **not** lowered; that would reject
  attributes accepted today). `F-146` returned `(nil, nil)` for an out-of-range
  m/n, handing back a contract with a nil code and no error. `F-183`, `F-184`,
  `F-128` (write side): swallowed encode/decode errors that produced truncated
  messages while reporting success. `F-128` **read** side deliberately deferred —
  requiring the header sentinel would reject inputs accepted today on consensus
  paths.

* **`ff8c6de`** — Nil-receiver guard on the async event-bus path into the
  transaction pool.

* **`a0152da`, `1a5aa44`** — **The nil class at the two checkpoint rebuild
  sites.** `a0152da` fixed two nil dereferences and **claimed** the rebuild then
  equalled a genesis-fresh object; `1a5aa44` shows that claim was wrong — it
  fixed the symptom and **unmasked a worse one**. A machine-generated reflective
  audit of every field found **nine** divergences, one genuinely reachable: an
  index-written map left nil, so gossip arriving after a reset or deep rollback
  and before the first block panics with *"assignment to entry in nil map"*
  (pre-existing upstream, not introduced by our F-096 work). **Operator:** the
  constructor now establishes the whole genesis baseline, and one builder serves
  both rebuild sites so they cannot drift apart. One deliberate divergence is
  documented and asserted (the rebuilt state gets its keyframe but not the
  subscriber closures — building those per reset would leak a subscription on
  every deep reorg). One **semantic delta** carried forward from F-096 is flagged
  for explicit core-engineer acknowledgement: a reset now clears the degradation
  state to normal instead of preserving a stale one.

**Networking, sync and pool retention**

* **`e9324d1`** — `F-136`: both DPoS hub read sites allocated from a wire uint32
  before any bound, so one unauthenticated TCP connection forced a **~4 GiB**
  allocation (measured 67 MB for a 64 MB claim, pristine); now capped at the same
  32 MB ceiling the writer already enforces. `F-148`: a disconnect with a request
  outstanding leaked a global entry that **permanently suppressed** re-requesting
  that DPoS address from every future peer. `F-198`: multisig verification
  re-hashed the whole transaction inside an O(sigs×n) loop — measured 422 502 →
  33 944 allocations, 0.61 s → 0.01 s. Behaviour-neutral hoist only; **no sigop
  cap**, deliberately, because decoding keys eagerly would flip currently
  accepted programs to rejected.

* **`e320c5f`** — P2P server/peer batch. `F-150`/`F-116`: `QueueMessage` blocked
  **forever** on a full queue whose only drainer had not started yet, wedging the
  single peer-handler goroutine and taking down peer management server-wide.
  `F-152`: a failed dial left a DNS seed disabled for the **lifetime of the
  process**. `F-154`: self-connection detection was entirely inert. `F-155`: the
  per-peer known-address set was unbounded. `F-157`: the negotiated protocol
  version was written back into shared config from another goroutine — a race and
  a global side effect. `F-213`: inbound peers could occupy **every** slot so the
  node could never dial out again — a cheap eclipse; inbound is now capped below
  `MaxPeers` with a floor of `MaxPeers/2`. `F-214`: ban scores for oversized
  block locators and filter loads.

* **`fb52e2f`** — `F-114`: the sync slot and target height were taken from an
  **unverified attacker-supplied** header height, and a claim of `0xffffffff`
  pinned the slot to that peer **forever** while every other peer's inventory was
  dropped; now clamped. `F-035`: the stall check lived where a hijacking peer's
  own behaviour prevented it from firing, and the timer reset on **any**
  delivered block including unconnectable orphans — so dripping one orphan just
  inside the timeout held the slot indefinitely; the check now runs from a ticker
  and resets only when our own tip advanced. `F-054`: a 33-byte inventory
  announcement caused a **full block load and deserialize** off the flat-file
  store, with no ban score anywhere on the path.

* **`5394f09`** — `F-092`: the block pool accepted any sanity-valid block at
  **any height** (the only work gate is a `PowLimit` of 2²⁵⁵−1) and the sweep only
  dropped entries *below* the reference, so a far-future block was retained for
  the process lifetime; a `uint32` underflow also dropped the **whole pool**
  — including the block being connected — during genesis bootstrap. `F-117`:
  orphan confirms, each costing the sender a single keypair, were retained
  forever. The membership check for confirms is **deferred** (acceptance-changing
  and redundant on both real paths).

* **`8a56f10`** — `FV-15`: the pool evicted by **height** while keyed by
  **hash**, so unlimited distinct blocks could sit at one retained height, and
  the sweep's only driver was the block-connected path — a stalled chain never
  swept. `FV-17`: a bounded queue drained into an **unbounded** pending list held
  for a ten-minute write timeout. `FV-14`: there is **no read deadline anywhere**
  in production DPoS P2P, and the handshake runs before the peer check and before
  the per-host limit, so a silent connection pinned a goroutine and an fd
  forever. `NX-07`: the persistent small-cross-transfer record was cleaned only
  on the block path, plus two leaked leveldb iterators.

* **`0907eb1`** — RPC/mempool hardening: `F-149` unbounded REST POST body;
  `F-161` WebSocket read limit, session cap and a torn-read race; `F-162`
  server timeouts; `F-163` a zero-count mining request that took the mining flags
  and never released them; `F-019` unfinalized transactions admitted to the pool;
  `F-060`/`F-120` fee-ordered eviction that was never reached; `F-193` a mined
  zero-input special transaction left in the pool. Also closes a real
  `Start`/`Stop` race on the server pointer.

* **`66bb738`** — `F-113`: six committee methods **wrote** state while holding
  only a **read** lock. `F-137`: two DPoS block-recovery stubs returned a **nil
  error**, telling the manager recovery had succeeded while nothing was appended;
  they now return an explicit "unimplemented" error (reviving the dormant
  protocol is an owner decision). `F-179`: a comparison helper was **fully
  inverted** (zero callers; fixed as a latent trap).

---

## 7. Durability and state growth

* **`6bd18d4`, `aa2cfb4`** — **F-096:** the DPoS checkpoint serialized the
  force-changed flag but **not** the degradation state, so a cold restart lost it
  and the startup replay re-triggered a **spurious emergency force-change**.
  Persisted as a trailing back-compatible block (legacy checkpoints default
  cleanly).

* **`7e342c6`, `7990622`** — **KS-ALIAS-01:** two producer maps are **alias
  indexes** holding the same pointer as one of the five owning state maps, but
  both persistence primitives allocate fresh objects, so after any restore or
  snapshot the index entry became a **stale frozen duplicate** — the mechanism
  behind the observed restore-baseline dependence of the persisted DPoS keyframe.
  Fixed by re-pointing at the canonical producer; **no key is ever added or
  removed**, which matters because one of those `len()`s is consensus-visible.
  `7990622` is a test-hardening follow-up after an adversarial pass **refuted the
  test, not the code**: three broken variants passed all six committed tests
  because every fixture started aliased, so direction and probe order were
  unobservable. It also **corrects the record** of the previous commit: one index
  is not `len()`-only — its values are read on a consensus path — but that read
  is dead for every restart-era block and touches only the immutable field the
  fix keys on.

* **`de69504`** — **F-142 / F-165:** a checkpoint deserializer read each entry
  off the wire and **never stored it**, so every round-trip or restart returned
  an **empty** map and wiped the pending real-withdraw queues → peer desync.
  Same commit: `F-074` (gate 1) a length mismatch between two independently
  counted slices was accepted and then **panicked on ProcessBlock** — a consensus
  halt; and `F-040`/`F-073` reorg-rollback fixes proven empirically.

* **`eef3fe5`** — **Checkpoint durability.** `F-122`: the save opened the
  **final** path with truncate *before* serializing anything and never fsynced,
  so a serialize error destroyed the good checkpoint on disk and a power cut left
  a short file that still "exists" — which is exactly the input `F-121` chokes
  on; now serialize to a buffer, write a sibling temp file, fsync, rename. The
  reply channel also stops reporting an unconditional success. `F-121`: a failed
  load left the live checkpoint half-populated **with the height read out of the
  bad file**, so the node ran at full block height with **empty CR/DPoS state**;
  the pre-load height is now restored so it falls back to full replay. `F-123`: a
  later success overwrote an earlier failure in the named return. `F-143`: two
  keyframe writers discarded per-entry errors, so a short write silently
  truncated and reported success. `F-138`: the node started with an **empty index,
  no tip and a nil best chain** when the authoritative record existed but the v2
  bucket did not; it now refuses to start. `F-145`'s headline is **refuted** (the
  disk path was correct; the omission was test-visible only). `F-187` recorded as
  gate-required and deferred.

* **`d72b378`** — **State growth.** `F-124`: the rollback persisted the
  **discarded child's** work sum next to the parent. `F-170`: `snapshot()` copied
  the maps but left a set nil and fourteen scalars zeroed — a snapshot was not a
  copy of the frame it came from. `F-209`: a map debited to zero never removed
  the entry, accumulating one permanent entry per stake address that ever voted —
  in RAM, in every serialized keyframe and in every deep copy. `F-018` and
  `F-207` recorded as **gate-required, deferred** (both are acceptance-changing);
  `F-194` **refuted** as written.

---

## 8. Configuration and startup safety

The single most dangerous configuration outcome is a node that resolves to
**mainnet identity** while its incident gates are **disabled** — it would follow
the corrupt chain and fork itself off the recovered fleet.

* **`68c0219`** — **F-043 part 1.** The params switch has **no default**, so an
  unrecognized label keeps full mainnet params, while the gate helpers switch on
  the **same string with a different case set** and send anything unrecognized to
  a default that disables **every** incident control. Empirically reproduced per
  label: `"mainet"`, `"MainNet "` (trailing space) and `"production"` all yield
  mainnet magic and mainnet genesis with freeze, strict-money and the rollback
  trigger **off**. **Operator:** labels are trimmed at all four switch sites (so
  whitespace-padded labels now resolve correctly), and an unrecognized label
  produces a loud stderr warning. Deliberately **not** fatal: an unknown label
  disabling the gates is a *tested, intentional* contract for private/forked
  nets.

* **`1012981`** — Prerequisite: a malformed `FoundationAddress` was parsed with
  the error **discarded**, so the genesis derivation nil-dereferenced ~40 lines
  later with a panic naming neither field nor cause — and that panic fired
  *before* the refuse-to-start gate could ever run, on exactly the malformed
  configs it targets.

* **`cbc8541`, `b214e6a`, `7b0b707`** — **F-043 part 2 / G3: refuse to start.**
  The guard discriminates by foundation **identity**, not by label (unknown
  labels are legitimate for private nets), and panics if any incident gate is
  disabled on a mainnet identity. `b214e6a` moves it **after** sterilization, or a
  private net with a custom foundation address would be falsely refused. `7b0b707`
  is the important hardening: `ArmIncidentGates` (below) is exactly what converts
  a caught typo into a **silent off-fleet mainnet node**, because its whole
  purpose is to stop the default arms disabling the pins — so no sentinel is left
  for a spot check to find. Observed on pristine: a node with the real mainnet
  foundation identity started with strict-money 999999999, forced-rollback height
  777777777, trigger `"deadbeef"`, freeze 666666666 and Schnorr 100 — gate 1
  effectively off, the rollback disarmed, the freeze off and the aggregate-Schnorr
  withdraw path re-opened, on a node that believes it is mainnet. The realistic
  path is a rehearsal `config.json` copied to a mainnet box with the label
  mistyped. **Operator:** the guard now refuses `ArmIncidentGates` outright on the
  mainnet identity, refuses unrecognized labels on that identity, and asserts
  **equality** with all 16 coordinated values (both gates, the two CrossChain-UTXO
  heights, the rollback height and trigger, all five Schnorr heights, the DPoSv2
  vote-lock bounds, the frozen-address list) instead of probing for sentinels —
  so a pin that a future mislabelled config bypasses is caught too. Every
  mismatch is reported in one message.

* **`e4237a4`, `633e347`** — **`ArmIncidentGates`.** **Was:** non-mainnet
  configurations had every incident gate hard-overwritten to disabled and
  `config.json` could not override it, so **every gate-1 fix was inert on
  testnet** and a green testnet run proved nothing about them. **Operator:** an
  opt-in flag lets a *non-mainnet* rehearsal chain honour the supplied heights
  and exercise the gated paths **with the same binary as mainnet**. The mainnet
  arm is untouched and runs first, so the flag is structurally incapable of
  weakening mainnet — locked in by a test that sets the flag together with
  hostile overrides across five mainnet label spellings.

* **`61c8e9e`** — Gate 2 was left **unpinned** for mainnet while gate 1 and the
  rollback values were pinned, even though it is CLI-overridable and
  consensus-affecting. A no-op while dormant, but once gate 2 has a value a
  mainnet override would silently diverge reward math from the fleet.

* **`0e9cf73`** — **Schnorr activation heights were not pinned.** The F-185 gate
  hangs off `SchnorrStartHeight`, which is mainnet-disabled but was settable from
  `config.json` and `--schnorrstartheight`. Two consequences of lowering it: the
  rogue-key aggregate withdraw path becomes dispatchable again, **and** the node
  rejects the V1 withdrawals the rest of the fleet accepts and forks itself off.
  All five activation heights in the family are now pinned to their compiled-in
  mainnet defaults — byte-identical for a correctly configured node; only an
  operator override is discarded, loudly. Testnet/regnet are deliberately
  untouched (they carry real Schnorr heights).

---

## 9. Cryptography and key material

* **`1f6bc9a`** — **F-059 (critical) and F-190: secret material drawn from
  `math/rand`.** F-059: the keystore IV (16 B) and master key (32 B) were drawn
  back-to-back from a generator seeded with the wall clock, and the IV is written
  to `keystore.dat` **in plaintext** — a 128-bit oracle that confirms a candidate
  seed, after which replaying the stream yields the master key, which decrypts
  every private key in the store. **The password is never involved.** Measured on
  this box: the seed lands 2.5–6 µs after a caller-observable timestamp and the
  search runs at ~100k seeds/s/core over 16 cores, so **one second of
  keystore-mtime uncertainty costs roughly ten minutes of brute force**; full
  master-key recovery reproduced 6/6. F-190: the Schnorr signing nonce came from
  the same globally re-seeded generator, so signing two messages under one seed
  reuses R — and the test **recovers the signing private key** from that pair.
  **Operator:** both now use `crypto/rand` with errors propagated. **This cannot
  repair existing files: every keystore created by any prior build is
  compromised at rest. Create a fresh keystore and migrate.** Deliberately *not*
  changed: the block-seeded generator behind arbiter selection — that is
  consensus-deterministic and replacing it would fork the chain.

* **`2734a9e`** — F-185, see [§4](#4-authorization-bypasses).

* **`47bb3d7`, `33e12f8`** — **F-205: producer payload signatures are
  context-free bearer credentials.** Proven against the production validator: the
  signature covers the payload alone — no network magic, no genesis hash, no
  nonce, no binding to the carrying transaction — so anyone can lift a published
  (payload, signature) pair off the chain, wrap it in a new transaction funded by
  an unrelated key, and roll a producer's node key or metadata back to that stale
  state. **No fix ships**; the fix space was closed empirically against the full
  2 260 597-block history and every candidate is worse than the defect:
  requiring an owner-bound program would reject 720/961 real update, 254/259
  register and **all 902** activate transactions; rejecting re-applied messages
  false-rejects 71 of 863 legitimate re-submissions; and domain-separating the
  signed message changes what **every wallet signs** and, gated at 2 260 451,
  activates on the first block of the recovery fork with no upgrade window. The
  headline "cross-network replay" is **refuted** for input-spending transactions.
  `33e12f8` then corrects **two overstatements in our own commit**: keying a
  blacklist on (message‖r) is *not* defeated by signature malleability (measured:
  zero duplicates across all four families in eight years), and the
  exploitability figure was ~10× overstated — only **14** producers are actually
  replayable at tip, all of them DPoSV1, so the headline liveness attack on
  arbiters is **not reachable at tip** by this path.

---

## 10. Build, tooling and test infrastructure

* **`e549b83`** — **Tooling hygiene.** `F-158`: CRC helper scripts echoed **raw
  private keys** to stdout and dumped the unlocked account with `%+v`, so the
  operator's own signing key went to shell history and CI logs. `F-159`: six
  white-box arbiter private keys were **compiled into `ela-cli`**; they move to a
  fixture file read at run time (values unchanged). `F-160`: two Lua type
  registrations collided on one global name, making one of them unreachable.
  `F-197`: a stray print echoed a caller's stake address on every RPC hit.
  `F-202`: candidate selection drew from the **process-global** generator shared
  with P2P and mining, so an interleaved draw shifted the selection — and the
  call **re-seeded every other consumer** from a public block hash; now a private
  block-seeded source, proven index-for-index identical over 200 000 real-shaped
  seeds. `F-210`: build-determinism pins — float contraction is
  architecture-dependent and cannot be fixed in Go source, so `.go-version` pins
  the exact toolchain patch (1.20.14), CI consumes it and no longer rewrites the
  module graph mid-build, and the Makefile gains a `GOAMD64` pin plus `release`
  (pinned GOOS/GOARCH/GOAMD64/CGO, `-trimpath`) and `repro-check` targets.
  `F-164` **refuted** on this tree; `F-211` deliberately not actioned (dependency
  bumps do not belong in a consensus batch).

* **`9d2be09`** — **The on-chain harness** (`cmd/onchainharness`), self-contained
  and importing the tree's own serialization so wire bytes are always faithful.
  Used to prove F-015 on a live rehearsal chain. Also records two grounded setup
  corrections found empirically, not from memory (reproducing DPoSV2 on a regnet
  needs **both** the DPoSV2 and the vote start heights lowered).

* **`bcb35d9`** — **G2: prove every guard is ARMED, not merely correct.** The
  blocker: **10 of 17 wiring mutations severed a live production guard with the
  entire suite green** — a test that asserts on a helper passes even when nothing
  calls the helper. Test-only (the production diff is empty): 19 new files, each
  failing when the production **call site** is removed; 45 production mutations
  run, **all 45 discriminated**. Reports two gaps rather than hiding them: three
  crash-guard tests live in packages outside the 8-suite gate, and
  `CalcPastMedianTime(nil)` panics three lines after an explicit nil guard
  (pre-existing at `d8488bf`, not fixed under a test-only mandate).

* **`7be226e`, `3d3ab1c`, `df066d4`, `7990622`, `633e347`** — Test-only commits
  that replace tests which passed on pristine, or which drove an internal helper
  instead of the production dispatch. Several are recorded as corrections to our
  own earlier evidence.

---

## 11. Documentation and corrected in-tree claims

* **`ce1ccd3`** — Comment-only. Corrects a WebSocket session-cap comment that
  claimed an overshoot "is bounded" without naming a bound (it is bounded by the
  attacker's connection concurrency, not by any constant of ours), and records
  that a snapshot-ring nil guard is belt-and-braces rather than the thing that
  clears the ring.

* **`4667fdf`** — Comment-only. Retracts a stale claim that a "height-gated
  F-057 fix" is active; at that commit there was none (see `ed54844`, which then
  closed it).

* **`8ebff84`**, **`33e12f8`**, **`1a5aa44`**, **`dcedb58`**, **`7990622`**,
  **`b50d37e`** each also correct a claim this campaign itself had made.

---

## 12. Release metadata

* **`be39057`** — **Version.** The tree carried **no** version string: the
  Makefile injected `git describe --dirty --always --tags`, so a release binary's
  identity was a property of the **builder's working copy**. Measured on the
  canonical tree with the pinned toolchain: a git checkout produced
  `ela-premerge-baseline-2526a6b-14-g2109` and a git-free export of the *same
  source* produced `ela-` (empty) — **two different binaries** (md5
  `1e3623d3…` vs `f255781b…`), which `make repro-check` cannot detect because it
  builds twice on one machine. **Operator:** `utils/version` now holds the single
  authoritative constant `Version = "v1.0.0"`; `ela --version`, `ela-cli
  --version`, `ela-dns -v`, the startup banner, the P2P user agent (`ela-v1.0.0`)
  and the RPC `compile` field all report it, and the release build no longer
  stamps it. Measured after: both a git checkout and a git-free export produce
  md5 `6f223764…` and report `ela-v1.0.0`. The `dev` target still stamps
  `<branch>-<sha>` so a development build stays self-identifying. No consensus
  code touched; no height literal added.

* **`0b3a9b1`** — this file and `RELEASE-MANIFEST.md`.

* **`29796fd`** — **Release assurance (B3).** `go.sum` is now **tracked** (587
  entries) rather than `.gitignore`d, so a fresh clone builds offline; CI actions
  are pinned by full SHA; `revive` is verified against a committed `sha256`
  before extraction; and a `check-toolchain` target refuses a build under any
  toolchain other than the pinned one. Also binds the profiler to the configured
  host (loopback by default) instead of every interface, and moves an
  illegal-confirm check ahead of a sanity check — a pure conjunction reorder, so
  the accepted set is byte-identical. Two defects in the original submission were
  fixed before it landed: a `go.sum` diff check that CI's own `go mod download`
  made fail on every run, and a `GOAMD64 :=` documented as blocking a
  command-line override, which only `override` actually does.

* **`78863f9`** — **Test-only.** Covers the production `submitauxblock` path
  end to end at and above gate 1 — the only path that produces mainnet blocks,
  and previously the largest untested surface in this release.

---

## Supply, measured

Because this release touches reward arithmetic, total supply was measured
directly rather than assumed. All 2,260,596 blocks were decoded with the
production codecs; all 35,327,231 transaction inputs resolved with **zero**
unresolved references, so fees are exact, not estimated. The result is
cross-checked against the UTXO set — which never touches coinbase arithmetic —
and the two agree **to the sela**.

| Measure | ELA |
|---|---:|
| Ever created (genesis 33,000,000 + all rewards paid + the 2019 excess below) | 39,740,390.63665694 |
| Still to be issued (every future block reward to the end of emission) | 1,479,607.15448400 |
| **Maximum ever creatable** | **41,219,997.79114094** |
| Burned to date (unspendable, at the destroy address) | 13,455,469.21450890 |
| **Maximum supply minus burned** | **27,764,528.57663204** |

The block reward is `800,000 ELA/year / 262,800 blocks / 2^(factor-1)`, the
factor stepping every 1,051,200 blocks (four years). Integer truncation takes it
to zero at height **30,484,800**, so the last paying block is 30,484,799 —
roughly 107 years out.

The ceiling reconciles exactly with the long-published maximum:
`41,219,997.79114094 - 13,000,000 (the proposal #1631 burn) = 28,219,997.79114094`.
The further 455,469.21 ELA of difference against the 27.76M figure above is the
three smaller burns (390,000 at height 173,672; 63,415.69 at 173,669; 2,030.26
accumulated from coinbases). **27.76M is an upper bound** — future burns only
reduce it — and it is not market circulating supply: it includes the CR
treasury, the staking pool, foundation holdings, cross-chain locks and the
1,585,252.00399183 ELA of frozen incident funds.

**Nothing in this release moves these numbers.** The ELA-only fee basis is
arithmetically identical on a chain that has never carried a non-ELA asset; the
empty-slot accounting fix guards a code path that has been unreachable since
height 1,413,580; and the forced rollback discards 144 blocks and re-mines them
at identical rewards.

### A historical over-issuance, disclosed

The same measurement found that **2.97238399 ELA was issued in July–August 2019
that the reward schedule does not account for.** It is disclosed here because
the figures above are published to eight decimal places and will not otherwise
reconcile.

Five blocks deviate, in both directions:

| Height | Deviation (ELA) | Shape |
|---:|---:|---|
| 425,865 | +1.75799087 | one block's arbiter share carried over |
| 433,533 | −63.30467656 | a round accumulated but was never paid |
| 434,847 | +1.75839344 | carry-over |
| 435,244 | +61.53523488 | a round paid a second time |
| 435,279 | +1.75995087 | carry-over |

Net, after a further 0.53450951 ELA left in an accumulator that was never
distributed at a version handover: **+2.97238399 ELA**.

The duplicate payment is **proven, not inferred**: blocks 435,243 and 435,244 —
consecutive, 54 seconds apart — carry **89 byte-identical (value, address)
reward pairs** totalling 63.29518528 ELA, differing only in the miner's own
output. The *mechanism* is inferred from source and has not been demonstrated:
the round-reward accumulator is cleared in only one function, and one branch of
the height-increase path calls neither it nor the clearing routine.

The excess went to ordinary arbiter and candidate addresses, so it is spendable
and was almost certainly spent years ago. **No fix is shipped and none is
proposed.** All five events used the V0 distribution routine, which — like the
empty-slot path — has been unreachable since height 1,413,580 behind a monotone
height test. Nothing in the evidence suggests intent; it has the shape of a bug
in the era immediately before the CR committee existed.

---

## Known limits of v1.0.0

**Read this before deploying.** These are the things this release does **not**
fix, does not prove, or leaves as an owner decision. Each is recorded in-tree at
its site.

### Open by owner decision

* **Gate 2's value (2 265 000) is pending core-engineer confirmation** and must
  be identical fleet-wide (`80378ab`).
* **F-205** (producer payload signatures are context-free bearer credentials) is
  **real and unfixed**. Every candidate fix is chain-breaking, ineffective, or a
  coordinated signing-message upgrade that cannot be gated at 2 260 451 without
  bricking producer/CR management ecosystem-wide. Its siblings — **F-129**
  (non-canonical ECDSA S), **F-189** (no proof-of-possession on node keys),
  **F-119**, **F-174**, **F-206** — must move together in one coordinated
  upgrade, not one at a time.
* **F-137**: the DPoS block-recovery protocol is inert and now fails loudly
  rather than lying about success. Reviving it is an owner decision.
* **F-134**, **F-201**, **F-156**: owner decisions, unchanged.

### Deferred because a fix would be acceptance-changing without a usable gate

Gate 1 (2 260 451) sits **below** the frozen tip 2 260 595, so a rule gated
there activates on the first block of the recovery fork with no upgrade window;
a third gate is not permitted. The following therefore ship unfixed:

* **F-018** (zero-value outputs and index membership), **F-207** (unbounded CR
  output maps), **F-187** (restart tip recovery), **F-128 read side** (header
  sentinel), **F-198** sigop budget, **F-117** confirm membership check,
  **F-040 part 2**, **F-072** DID/CustomID uniqueness, **F-119**
  (`ActivateProducer` same-block arming).
* **F-030 minor residual:** evidence whose own height is below gate 1 but whose
  transaction is included above it stays raw-keyed and therefore still malleable.
  Exposure is negligible (documented in `2b4b662`) but it is open.
* **F-091** partially: the core/transaction copy of the cross-chain signature
  check is caller-guarded and deliberately untouched.

### Proven mechanism, but realized value movement **not** demonstrated

Per the standing rule that inflation and mint claims are never inferred:

* The multi-block **drains** behind F-028 / F-066 / F-067 / F-078 and the
  cross-chain double-refund / double-credit behind F-016 / F-017 need a
  multi-block state machine that was not stood up. The **in-block** conflicts are
  empirically proven; the drains are **NEEDS-SIM**.
* **F-104 / F-118** have no live sidechain proof — the sidechain testbed is
  deferred by owner decision. They are shipped as gated fixes, **not** claimed
  closed.
* **F-011/086** is classified **DORMANT** by a full-chain measurement (zero
  non-ELA outputs, ever), not by a live exploit.
* **NX-06** live behaviour is **inferred** from source and unit tests on the
  production call path; **no live mesh was run**.
* **F-093** has **no live multi-node reorg simulation**; the proof is unit-level
  against the real force-change path.

### Residual exposure that remains open by design

* **F-032**: a producer may still name any current or last arbiter and
  redistribute a **conserved, non-inflationary** sponsor reward. Accepted in
  `f6ea5b2` because the only convergent alternative was a permanent consensus
  split.
* **NX-06 below gate 1**: a malicious sync peer can still poison a node replaying
  the historical POW windows (all below 2 129 102) and halt its initial sync.
  Closed for the restarted fleet; **not** closed for a node joining by full sync
  from genesis. **Restart-runbook item.**
* **F-057 / FV-22 option (b)** raises emergency failsafe latency from **~2 h to
  ~4 h**. 28 of 29 historical rescues would have had to wait longer.
* **F-036**: REST and WebSocket still have **no authentication**. Lifting it was
  deliberately not shipped because it would 403 every cross-host consumer on
  upgrade. Firewall 20333/20334/20335, or disable those services, if they are not
  needed.
* **Keystores created by any prior build are compromised at rest** (F-059) and
  this release cannot repair them. Also untouched, separate finding classes: the
  password KDF is unsalted double-SHA256, and keystore AES-CBC has no
  authentication tag.
* A **pre-existing** `a.mtx ↔ s.mtx` AB-BA lock inversion, present byte-for-byte
  at `d8488bf`, is reported in `17f1c09` and deliberately not touched.
* `CalcPastMedianTime(nil)` panics, reported in `bcb35d9` under a test-only
  mandate.
* The second pprof surface via the profiler binds all interfaces regardless of
  the configured host — but only when `ProfilePort != 0`, which is off by
  default.
* Testnet and regnet keep real Schnorr activation heights and gate 1 disabled, so
  the F-185 acceptance rule never fires there and their V2 withdrawals keep the
  rogue-key-vulnerable plain-sum aggregate. Config decision.
* The **plain-sum Schnorr aggregate remains rogue-key-vulnerable as code**
  wherever `SchnorrStartHeight` is genuinely enabled. A MuSig or
  proof-of-possession fix must land in lockstep with `Elastos.ELA.Arbiter`.

### Not in this release at all

* Any change to `Elastos.ELA.Arbiter`, `Elastos.ELA.SideChain.*` or the ESC/EID
  side chains. This release is **main chain only**.
* Any recovery, burn or fund-movement action. Those are separate, later,
  owner-driven operations.
* A verified delta against **released upstream v0.9.9.6** — see
  `RELEASE-MANIFEST.md`, where that field is **OPEN and BLOCKED**.
