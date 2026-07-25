// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
)

// PreflightOutcome is the answer to "what will happen when I start this node".
type PreflightOutcome string

const (
	// PreflightWillRewind -- the forced rollback is armed and will run.
	PreflightWillRewind PreflightOutcome = "will-rewind"
	// PreflightNothingToDo -- the node starts and the rollback does not run,
	// because it is already applied or because this node never held the chain.
	PreflightNothingToDo PreflightOutcome = "nothing-to-do"
	// PreflightWillRefuse -- the node will exit rather than start.
	PreflightWillRefuse PreflightOutcome = "will-refuse-to-start"
	// PreflightUnknown -- the store could not be read (locked, missing).
	PreflightUnknown PreflightOutcome = "unknown"
)

// PreflightGates reports the consensus heights AFTER the mainnet pin has run, and
// whether the pin discarded anything the operator supplied.
type PreflightGates struct {
	ActiveNet               string `json:"active_net"`
	IsMainNet               bool   `json:"is_mainnet"`
	StrictMoneyRangeHeight  uint32 `json:"strict_money_range_height"`
	RevisedDPoSRewardHeight uint32 `json:"revised_dpos_reward_height"`
	ForcedRollbackHeight    uint32 `json:"forced_rollback_height"`
	ForcedRollbackTrigger   string `json:"forced_rollback_trigger"`
	// DiscardedOverrides names config.json fields / CLI flags whose value the
	// mainnet pin threw away. Empty on a correctly configured node.
	DiscardedOverrides []string `json:"discarded_overrides,omitempty"`
}

// PreflightStoreState is everything the pre-flight read out of the persisted store.
type PreflightStoreState struct {
	DataDir string `json:"data_dir"`
	// Tip is the block-index tip a boot would load.
	Tip uint32 `json:"tip"`
	// TriggerPresent and the three index flags say where the targeted block still
	// lives. All are read from the database, never from the in-RAM index.
	TriggerPresent  bool   `json:"trigger_present"`
	OnMainChain     bool   `json:"trigger_on_main_chain"`
	MainChainHeight uint32 `json:"trigger_main_chain_height,omitempty"`
	HeaderRow       bool   `json:"trigger_header_row"`
	InBlockStore    bool   `json:"trigger_in_block_store"`
	// MarkerPresent reports a durable interrupted-rewind marker.
	MarkerPresent bool   `json:"rewind_marker_present"`
	MarkerTarget  uint32 `json:"rewind_marker_target,omitempty"`
	MarkerStart   uint32 `json:"rewind_marker_start,omitempty"`
	// Residue counts come from a full store census, and are only populated on the
	// boots that actually run one (see Estimate.FullStoreScans).
	Scanned         bool   `json:"residue_scanned"`
	LiveAbove       int    `json:"live_above_target,omitempty"`
	MainChainAbove  int    `json:"main_chain_above_target,omitempty"`
	StoredAbove     int    `json:"stored_above_target,omitempty"`
	HeaderRowsAbove int    `json:"header_rows_above_target,omitempty"`
	BestStateHeight uint32 `json:"best_state_height,omitempty"`
	// SizeBytes is the on-disk size of the block database.
	SizeBytes int64 `json:"size_bytes"`
	// NewestWrite is the newest mtime among the store's files. It is EVIDENCE,
	// not proof, about when this data directory was last written.
	NewestWrite time.Time `json:"newest_write"`
	// PendingUncleanShutdownRepair describes flat-file truncation the node will
	// perform on its next read-write open, or "".
	PendingUncleanShutdownRepair string `json:"pending_unclean_shutdown_repair,omitempty"`
}

// PreflightEstimate is how long the forced-rollback work will take, from MEASURED
// numbers. It is an estimate and says so.
type PreflightEstimate struct {
	FullStoreScans int    `json:"full_store_scans"`
	LowSeconds     int    `json:"low_seconds"`
	HighSeconds    int    `json:"high_seconds"`
	Basis          string `json:"basis"`
}

// PreflightReport is the whole answer, renderable as text or JSON.
type PreflightReport struct {
	Version  string              `json:"binary_version"`
	Gates    PreflightGates      `json:"gates"`
	Store    PreflightStoreState `json:"store"`
	Cell     string              `json:"truth_table_cell"`
	Outcome  PreflightOutcome    `json:"outcome"`
	Headline string              `json:"headline"`
	// Blocking lists everything that will stop a successful start. Non-empty
	// exactly when Outcome is will-refuse-to-start.
	Blocking []string `json:"blocking,omitempty"`
	// Warnings are things the operator must think about that do NOT stop the
	// node. They deliberately do not change the exit code.
	Warnings []string          `json:"warnings,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
	Estimate PreflightEstimate `json:"estimate"`
}

// measuredScanSeconds is one full ScanForcedRollbackStore pass over the 25 GiB
// mainnet store. MEASURED: an armed boot spent ~34 s in three such scans.
const measuredScanSeconds = 11.3

// measuredStoreGiB is the store the timings above were measured on.
const measuredStoreGiB = 25.0

// measuredArmedBootLowSeconds/HighSeconds is the whole armed boot on that store.
const (
	measuredArmedBootLowSeconds  = 66.0
	measuredArmedBootHighSeconds = 73.0
)

// PreflightOptions carries the paths the report needs beyond the chain itself.
type PreflightOptions struct {
	// Version is the binary's version string. It is passed in rather than
	// imported so package blockchain does not depend on utils/version, and it is
	// set BEFORE the report is built because the stale-data warning quotes it.
	Version string
	// DataDir is the CHAIN DATA directory (<node dir>/data).
	DataDir string
	// NodeDir is its parent, where logs/ lives. May be empty.
	NodeDir string
	// SuppliedTrigger/SuppliedHeight are what the operator's configuration asked
	// for BEFORE the mainnet pin ran, so the report can say what was discarded.
	SuppliedTrigger string
	SuppliedHeight  uint32
	HeightSupplied  bool
	TriggerSupplied bool
}

// BuildPreflightReport predicts the next start of this node.
//
// It walks main.go's forced-rollback boot sequence IN MAIN.GO'S ORDER, calling the
// production checks that only read and the extracted diagnoses of the two that act,
// and stops at the first one that decides the outcome. Nothing here restates a
// boot-path condition: every branch below is either a production function's return
// value or a production diagnosis state.
func BuildPreflightReport(chain *BlockChain, opts PreflightOptions) (
	*PreflightReport, error) {
	params := chain.chainParams
	r := &PreflightReport{
		Version: opts.Version,
		Gates: PreflightGates{
			ActiveNet:               params.ActiveNet,
			IsMainNet:               config.IsMainNetActiveNet(params.ActiveNet),
			StrictMoneyRangeHeight:  params.StrictMoneyRangeHeight,
			RevisedDPoSRewardHeight: params.RevisedDPoSRewardHeight,
			ForcedRollbackHeight:    params.ForcedRollbackHeight,
			ForcedRollbackTrigger:   params.ForcedRollbackTrigger,
		},
		Store: PreflightStoreState{DataDir: opts.DataDir},
	}
	r.Gates.DiscardedOverrides = discardedRollbackOverrides(params, opts)
	r.Store.Tip = chain.GetHeight()
	// The chain data directory as a whole, because that is the unit the 66-73 s
	// baseline was measured in ("a 25 GB store"). Scaling by the blocks/
	// sub-directory alone would understate the very store the number came from.
	r.Store.SizeBytes, r.Store.NewestWrite = measureStore(opts.DataDir)
	r.Store.PendingUncleanShutdownRepair = PendingUncleanShutdownRepair(chain.db)

	if err := r.readTriggerLocation(chain); err != nil {
		return nil, err
	}
	if err := r.readMarker(chain); err != nil {
		return nil, err
	}
	if r.Store.PendingUncleanShutdownRepair != "" {
		r.Warnings = append(r.Warnings, "This store was left by an UNCLEAN SHUTDOWN. "+
			"The node will roll its flat block files back to the metadata's write "+
			"cursor on start ("+r.Store.PendingUncleanShutdownRepair+"). The "+
			"pre-flight did NOT perform that repair, so the numbers above describe "+
			"the store as it is on disk now.")
	}

	if err := r.predict(chain, opts); err != nil {
		return nil, err
	}
	r.addStaleDataFinding(chain, opts)
	return r, nil
}

// predict is main.go's sequence, in main.go's order.
func (r *PreflightReport) predict(chain *BlockChain, opts PreflightOptions) error {
	target := chain.chainParams.ForcedRollbackHeight

	// (1) CheckAbandonedForcedRollback -- runs on EVERY boot, configured or not,
	// and is already pure-read.
	if err := chain.CheckAbandonedForcedRollback(); err != nil {
		r.refuse("I", err,
			"This node will REFUSE to start: its store records a forced rollback "+
				"that STARTED and never finished, and this node is not configured "+
				"to finish it.")
		return nil
	}

	if !chain.forcedRollbackConfigured() {
		// Cell F. Nothing in the forced-rollback path runs at all.
		r.Cell = "F/no-forced-rollback-configured"
		r.Outcome = PreflightNothingToDo
		r.Headline = fmt.Sprintf("No forced rollback is configured for network %q, "+
			"so nothing in the rollback path will run on start.", chain.chainParams.ActiveNet)
		if r.Store.TriggerPresent {
			r.Warnings = append(r.Warnings, "The store still holds the block a "+
				"forced rollback would target, but this binary's configuration has "+
				"the rollback DISABLED, so this node will start on that chain.")
		}
		r.Estimate = estimate(0, r.Store.SizeBytes)
		return nil
	}

	// (2) ForcedRollbackArmed.
	armed, err := chain.ForcedRollbackArmed()
	if err != nil {
		r.refuse("", err, "This node will REFUSE to start: the configured "+
			"forced-rollback trigger cannot be parsed.")
		return nil
	}

	if armed {
		// (3a) PreflightForcedRollback, then ForceRollback's capacity refusal.
		p, err := chain.DiagnoseForcedRollbackPreflight()
		if err != nil {
			return err
		}
		if p.Scan != nil {
			r.recordScan(p.Scan)
		}
		if p.State == RewindPreflightDamaged {
			r.refuse("", p.Err, "This node will REFUSE to start: the store carries "+
				"partial-rollback damage the rewind cannot repair.")
			r.Estimate = estimate(1, r.Store.SizeBytes)
			return nil
		}
		depth := r.Store.Tip - target
		if p.State == RewindPreflightCapacitySkipped {
			r.refuse("G", fmt.Errorf("forced rollback depth %d exceeds history "+
				"capacity %d; the node refuses to rewind incrementally and refuses "+
				"to start. %s", depth, maxHistoryCapacity,
				chain.forcedRollbackDisarmRemedy()),
				fmt.Sprintf("This node will REFUSE to start: it is %d blocks past "+
					"the rollback target %d, which is beyond the %d-block "+
					"incremental rewind window.", depth, target, maxHistoryCapacity))
			// No full store scan runs on this boot: PreflightForcedRollback steps
			// aside on capacity before it censuses anything, and ForceRollback
			// refuses before it does either.
			r.Estimate = estimate(0, r.Store.SizeBytes)
			return nil
		}
		r.Cell = "A-or-E/holds-the-chain-the-recovery-removes"
		r.Outcome = PreflightWillRewind
		r.Headline = fmt.Sprintf("This node WILL REWIND on start: from tip %d down "+
			"to %d, discarding %d block(s), starting with the block the recovery "+
			"removes (%s at height %d).", r.Store.Tip, target, depth,
			chain.chainParams.ForcedRollbackTrigger, target+1)
		if r.Store.MarkerPresent {
			r.Notes = append(r.Notes, fmt.Sprintf("An earlier rewind to target %d "+
				"was interrupted (it started at tip %d). This start RESUMES it; the "+
				"rewind is resumable and exactly-once, so nothing is rolled back twice.",
				r.Store.MarkerTarget, r.Store.MarkerStart))
		}
		r.Estimate = estimate(3, r.Store.SizeBytes)
		return nil
	}

	// (3b) CheckForcedRollbackResidue, through its extracted diagnosis.
	d, err := chain.DiagnoseForcedRollbackResidue()
	if err != nil {
		return err
	}
	scans := 0
	if d.Scan != nil {
		scans = 1
		r.recordScan(d.Scan)
	}
	if d.State == ResidueInterrupted {
		r.refuse("", d.Err, "This node will REFUSE to start: the block database "+
			"still records blocks above the rollback target as main chain while "+
			"the loaded tip does not -- an interrupted rollback whose UTXO and "+
			"derived-state processors never ran.")
		r.Estimate = estimate(scans, r.Store.SizeBytes)
		return nil
	}
	if d.State == ResidueRetentionOnly {
		r.Notes = append(r.Notes, fmt.Sprintf("On start the node will purge %d "+
			"discarded block(s) and %d orphaned header row(s) above the target. "+
			"That is retention residue only -- the main chain is consistent.",
			len(d.Scan.StoredAbove), len(d.Scan.HeaderRowsAbove)))
	}
	if d.Marker != nil && d.MarkerErr == nil && d.State != ResidueInterrupted {
		r.Notes = append(r.Notes, fmt.Sprintf("On start the node will clear a stale "+
			"in-progress marker (target %d, start %d); the store is clean above the "+
			"target.", d.Marker.Target, d.Marker.Start))
	}

	// (4) VerifyForcedRollbackApplied, through its extracted diagnosis.
	a, err := chain.DiagnoseForcedRollbackApplied()
	if err != nil {
		return err
	}
	switch a.State {
	case ApplyTriggerHeightMismatch:
		r.refuse("H", a.Err, fmt.Sprintf("This node will REFUSE to start: the "+
			"configured trigger names the block at height %d, but the rollback is "+
			"defined as removing the block at height %d. One of the two configured "+
			"values is wrong.", a.TriggerHeight, target+1))
	case ApplyTriggerOnMainChain:
		r.refuse("", a.Err, "This node will REFUSE to start: the block the recovery "+
			"removes is still recorded on the MAIN CHAIN, so its UTXO and "+
			"derived-state effects were never reverted.")
	case ApplyRetentionResidue:
		r.Cell = "C/already-rewound/retention-residue"
		r.Outcome = PreflightNothingToDo
		r.Headline = fmt.Sprintf("Nothing to roll back: the rollback is already "+
			"applied on this store (tip %d). On start the node will purge the "+
			"discarded block's residual %s and continue.", r.Store.Tip,
			residueWords(a.Loc))
	case ApplySettled:
		r.Outcome = PreflightNothingToDo
		switch {
		case r.Store.Tip > target:
			r.Cell = "C/already-rewound/moved-forward-on-the-recovered-chain"
			r.Headline = fmt.Sprintf("Nothing to roll back: the rollback is ALREADY "+
				"APPLIED and this node has moved forward on the recovered chain "+
				"(tip %d, target %d). The rewind cannot arm on this store.",
				r.Store.Tip, target)
		case r.Store.Tip == target:
			r.Cell = "B-or-D/at-the-target"
			r.Headline = fmt.Sprintf("Nothing to roll back: this node's tip is "+
				"exactly the rollback target %d and the block the recovery removes "+
				"is absent from all three persisted indexes. The rewind will not "+
				"run on this start.", target)
		default:
			r.Cell = "D/below-the-target"
			r.Headline = fmt.Sprintf("Nothing to roll back: this node's tip is %d, "+
				"below the rollback target %d, so it never held the block the "+
				"recovery removes. It will sync forward on the recovered chain.",
				r.Store.Tip, target)
		}
	case ApplyNotConfigured:
		// Unreachable: forcedRollbackConfigured was checked above.
		r.Cell = "F/no-forced-rollback-configured"
		r.Outcome = PreflightNothingToDo
		r.Headline = "No forced rollback is configured."
	}
	r.Estimate = estimate(scans, r.Store.SizeBytes)
	return nil
}

// refuse records a will-not-start outcome with the production error text verbatim.
func (r *PreflightReport) refuse(cell string, err error, headline string) {
	if cell != "" {
		r.Cell = cell
	} else if r.Cell == "" {
		r.Cell = "refusal"
	}
	r.Outcome = PreflightWillRefuse
	r.Headline = headline
	r.Blocking = append(r.Blocking, err.Error())
}

// readTriggerLocation fills the three persisted-index flags.
func (r *PreflightReport) readTriggerLocation(chain *BlockChain) error {
	loc, err := chain.LocateForcedRollbackTrigger()
	if err != nil {
		return err
	}
	if loc == nil {
		return nil
	}
	r.Store.TriggerPresent = loc.Present()
	r.Store.OnMainChain = loc.OnMainChain
	r.Store.MainChainHeight = loc.MainChainHeight
	r.Store.HeaderRow = loc.HeaderRow
	r.Store.InBlockStore = loc.InBlockStore
	return nil
}

// readMarker fills the interrupted-rewind marker fields.
func (r *PreflightReport) readMarker(chain *BlockChain) error {
	marker, err := chain.ReadForcedRollbackMarker()
	if err != nil {
		// An unreadable marker is itself a finding, not a reason to fail: report it
		// and carry on, because CheckAbandonedForcedRollback will refuse on it.
		r.Warnings = append(r.Warnings, "The in-progress rollback marker is "+
			"unreadable: "+err.Error())
		return nil
	}
	if marker == nil {
		return nil
	}
	r.Store.MarkerPresent = true
	r.Store.MarkerTarget = marker.Target
	r.Store.MarkerStart = marker.Start
	return nil
}

// recordScan copies a census into the report.
func (r *PreflightReport) recordScan(scan *ForcedRollbackStoreScan) {
	r.Store.Scanned = true
	r.Store.LiveAbove = len(scan.LiveAbove)
	r.Store.MainChainAbove = len(scan.MainChainAbove)
	r.Store.StoredAbove = len(scan.StoredAbove)
	r.Store.HeaderRowsAbove = len(scan.HeaderRowsAbove)
	r.Store.BestStateHeight = scan.BestStateHeight
}

// residueWords names which residual records the boot will purge.
func residueWords(loc *ForcedRollbackTriggerLocation) string {
	var parts []string
	if loc.HeaderRow {
		parts = append(parts, "block-header-index row")
	}
	if loc.InBlockStore {
		parts = append(parts, "raw block-store entry")
	}
	if len(parts) == 0 {
		return "records"
	}
	return strings.Join(parts, " and ")
}

// discardedRollbackOverrides names the operator-supplied values the mainnet pin
// threw away, using the SAME comparison announceDiscardedRollbackOverride makes.
func discardedRollbackOverrides(params *config.Configuration,
	opts PreflightOptions) []string {
	if !config.IsMainNetActiveNet(params.ActiveNet) {
		return nil
	}
	var out []string
	if opts.TriggerSupplied && opts.SuppliedTrigger != config.MainNetForcedRollbackTrigger {
		out = append(out, fmt.Sprintf("ForcedRollbackTrigger %q was DISCARDED and "+
			"re-pinned to %s. There is no way to disarm the forced rollback on a "+
			"mainnet node.", opts.SuppliedTrigger, config.MainNetForcedRollbackTrigger))
	}
	if opts.HeightSupplied && opts.SuppliedHeight != config.MainNetForcedRollbackHeight {
		out = append(out, fmt.Sprintf("ForcedRollbackHeight %d was DISCARDED and "+
			"re-pinned to %d.", opts.SuppliedHeight, config.MainNetForcedRollbackHeight))
	}
	return out
}

// estimate scales the MEASURED timings by store size.
func estimate(scans int, sizeBytes int64) PreflightEstimate {
	ratio := float64(sizeBytes) / (measuredStoreGiB * 1024 * 1024 * 1024)
	e := PreflightEstimate{FullStoreScans: scans}
	switch scans {
	case 0:
		e.LowSeconds, e.HighSeconds = 0, 1
		e.Basis = "no full store scan runs on this boot -- the forced-rollback " +
			"checks are three point lookups. MEASURED on the 25 GiB mainnet store."
	case 3:
		e.LowSeconds = int(measuredArmedBootLowSeconds * ratio)
		e.HighSeconds = int(measuredArmedBootHighSeconds*ratio) + 1
		e.Basis = fmt.Sprintf("ESTIMATE. MEASURED: an armed boot on a 25 GiB store "+
			"took 66-73 s, of which ~34 s was three full store scans at ~%.0f s "+
			"each. Scaled linearly by this store's size (%.1f GiB).",
			measuredScanSeconds, ratio*measuredStoreGiB)
	default:
		e.LowSeconds = int(measuredScanSeconds * float64(scans) * ratio)
		e.HighSeconds = int(measuredScanSeconds*float64(scans)*ratio*1.2) + 1
		e.Basis = fmt.Sprintf("ESTIMATE, for the forced-rollback scanning only "+
			"(the rest of node startup is not included). MEASURED: one full store "+
			"scan took ~%.0f s on a 25 GiB store; this boot runs %d. Scaled "+
			"linearly by this store's size (%.1f GiB).",
			measuredScanSeconds, scans, ratio*measuredStoreGiB)
	}
	return e
}

// measureStore returns the on-disk size of the block database and the newest mtime
// among its files.
func measureStore(blocksDir string) (int64, time.Time) {
	var total int64
	var newest time.Time
	_ = filepath.Walk(blocksDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return total, newest
}
