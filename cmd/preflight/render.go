// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package preflight

import (
	"fmt"
	"strings"

	"github.com/elastos/Elastos.ELA/blockchain"
)

// RenderText renders the report for a human, on stdout.
//
// It is separate from the command so it can be tested without a CLI context, and
// so the JSON form and the text form are provably the same report: both are built
// from one *PreflightReport and neither computes anything of its own.
//
// The layout puts THE PREDICTION first. On restart day an operator reads the top
// of the output; identity and store detail are evidence for the sentence above
// them, not a preamble to scroll past.
func RenderText(r *blockchain.PreflightReport) string {
	var b strings.Builder
	line := strings.Repeat("=", 78)

	fmt.Fprintf(&b, "%s\nELA NODE PRE-FLIGHT -- what will happen when you start this node\n%s\n\n",
		line, line)

	fmt.Fprintf(&b, "  %s\n\n", strings.ToUpper(string(r.Outcome)))
	for _, l := range wrap(r.Headline, 74) {
		fmt.Fprintf(&b, "  %s\n", l)
	}
	fmt.Fprintf(&b, "\n  Estimated time: ")
	if r.Estimate.HighSeconds <= 1 {
		fmt.Fprintf(&b, "under a second\n")
	} else {
		fmt.Fprintf(&b, "%d-%d seconds (%d full store scan(s))\n",
			r.Estimate.LowSeconds, r.Estimate.HighSeconds, r.Estimate.FullStoreScans)
	}
	for _, l := range wrap(r.Estimate.Basis, 72) {
		fmt.Fprintf(&b, "    %s\n", l)
	}

	if len(r.Blocking) > 0 {
		fmt.Fprintf(&b, "\n%s\nBLOCKING -- this is what the node itself will print, and then exit\n%s\n",
			line, line)
		for _, blocker := range r.Blocking {
			for _, l := range wrap(blocker, 76) {
				fmt.Fprintf(&b, "  %s\n", l)
			}
			fmt.Fprintln(&b)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "\n%s\nWARNINGS -- these do NOT stop the node, and do not change the exit code\n%s\n",
			line, line)
		for _, w := range r.Warnings {
			for i, l := range wrap(w, 74) {
				prefix := "  ! "
				if i > 0 {
					prefix = "    "
				}
				fmt.Fprintf(&b, "%s%s\n", prefix, l)
			}
			fmt.Fprintln(&b)
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprintf(&b, "\n%s\nNOTES\n%s\n", line, line)
		for _, n := range r.Notes {
			for i, l := range wrap(n, 74) {
				prefix := "  - "
				if i > 0 {
					prefix = "    "
				}
				fmt.Fprintf(&b, "%s%s\n", prefix, l)
			}
		}
	}

	fmt.Fprintf(&b, "\n%s\nIDENTITY -- the binary, and the gates AFTER the mainnet pin has run\n%s\n", line, line)
	fmt.Fprintf(&b, "  binary version              %s\n", r.Version)
	fmt.Fprintf(&b, "  active net                  %s (mainnet=%v)\n",
		netLabel(r.Gates.ActiveNet), r.Gates.IsMainNet)
	fmt.Fprintf(&b, "  StrictMoneyRangeHeight      %s\n", height(r.Gates.StrictMoneyRangeHeight))
	fmt.Fprintf(&b, "  RevisedDPoSRewardHeight     %s\n", height(r.Gates.RevisedDPoSRewardHeight))
	fmt.Fprintf(&b, "  ForcedRollbackHeight        %s\n", height(r.Gates.ForcedRollbackHeight))
	fmt.Fprintf(&b, "  ForcedRollbackTrigger       %s\n", triggerLabel(r.Gates.ForcedRollbackTrigger))
	for _, d := range r.Gates.DiscardedOverrides {
		for i, l := range wrap(d, 72) {
			prefix := "  ! "
			if i > 0 {
				prefix = "    "
			}
			fmt.Fprintf(&b, "%s%s\n", prefix, l)
		}
	}

	fmt.Fprintf(&b, "\n%s\nSTORE -- read from the persisted database, never from the in-RAM index\n%s\n", line, line)
	fmt.Fprintf(&b, "  data directory              %s\n", r.Store.DataDir)
	fmt.Fprintf(&b, "  block database size         %.1f GiB\n",
		float64(r.Store.SizeBytes)/(1024*1024*1024))
	fmt.Fprintf(&b, "  newest write in the store   %s\n",
		r.Store.NewestWrite.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "  block index tip             %d\n", r.Store.Tip)
	fmt.Fprintf(&b, "  trigger block present       %v\n", r.Store.TriggerPresent)
	if r.Store.TriggerPresent {
		fmt.Fprintf(&b, "    on the main chain         %v", r.Store.OnMainChain)
		if r.Store.OnMainChain {
			fmt.Fprintf(&b, " (at height %d)", r.Store.MainChainHeight)
		}
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "    header-index row          %v\n", r.Store.HeaderRow)
		fmt.Fprintf(&b, "    raw block store           %v\n", r.Store.InBlockStore)
	}
	fmt.Fprintf(&b, "  interrupted-rewind marker   %v", r.Store.MarkerPresent)
	if r.Store.MarkerPresent {
		fmt.Fprintf(&b, " (target %d, started from tip %d)",
			r.Store.MarkerTarget, r.Store.MarkerStart)
	}
	fmt.Fprintln(&b)
	if r.Store.Scanned {
		fmt.Fprintf(&b, "  residue above the target    live=%d main-chain=%d stored=%d header-rows=%d\n",
			r.Store.LiveAbove, r.Store.MainChainAbove, r.Store.StoredAbove,
			r.Store.HeaderRowsAbove)
		fmt.Fprintf(&b, "  persisted best-state height %d\n", r.Store.BestStateHeight)
	} else {
		fmt.Fprintf(&b, "  residue above the target    not censused on this boot (no full store scan runs)\n")
	}
	fmt.Fprintf(&b, "  restored checkpoint height  %d (upper bound; header read, file not loaded)\n",
		r.Store.RestoredCheckpointMaxHeight)
	for _, c := range r.Store.RestoredCheckpoints {
		counted := ""
		if !c.CountedInMaxHeight {
			counted = "  [not counted]"
		}
		if c.Err != "" {
			fmt.Fprintf(&b, "    %-24s restores no height%s\n", c.Key, counted)
			continue
		}
		fmt.Fprintf(&b, "    %-24s %d  (%s)%s\n", c.Key, c.Height, c.File, counted)
	}
	fmt.Fprintf(&b, "  post-restore height check   %s\n",
		checkpointGateWords(r.Store.CheckpointGateEvaluated))
	fmt.Fprintf(&b, "  truth-table cell            %s\n", r.Cell)

	fmt.Fprintf(&b, "\n%s\nThis command read the store and wrote nothing to it.\n%s\n", line, line)
	return b.String()
}

// checkpointGateWords says plainly whether main.go's post-restore height refusal
// applies to this start, so the height above is never read as a bare number the
// operator has to interpret.
func checkpointGateWords(evaluated bool) string {
	if evaluated {
		return "RUNS on this start (refuses if the height above >= the rollback target)"
	}
	return "does not apply to this start"
}

// height renders the disabled sentinel as words rather than 4294967295.
func height(h uint32) string {
	if h == 4294967295 {
		return "disabled (max uint32)"
	}
	return fmt.Sprint(h)
}

// triggerLabel renders an empty trigger as words.
func triggerLabel(t string) string {
	if t == "" {
		return "(none -- forced rollback disabled)"
	}
	return t
}

// netLabel renders the empty ActiveNet, which means mainnet.
func netLabel(n string) string {
	if strings.TrimSpace(n) == "" {
		return `"" (mainnet)`
	}
	return n
}

// wrap breaks a paragraph at width, on spaces.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			out = append(out, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(out, cur)
}
