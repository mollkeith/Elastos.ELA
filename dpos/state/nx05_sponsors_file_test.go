// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-05 (Tier 0) — the operator-local `sponsors` file must not be able to make two honest
// nodes disagree, and must not be able to kill a node at startup.
//
// The file populates BlockConfirmProposalSponsors, which is consensus-bearing:
// Arbiters.ProcessBlock substitutes its entry for the sponsor handed to
// State.ProcessBlock -> countArbitratorsInactivity*, and the pre-RecordSponsorStartHeight
// branch of accumulateReward credits rewards through it. As shipped it was read from a
// BARE RELATIVE PATH against the process working directory, every read failure was
// swallowed with one log.Warn, a single comma-less line PANICKED the node inside
// NewArbitrators, and a negative height silently wrapped to a uint32 near 2^32.
//
// The map's third and worst site — block VALIDITY, via CheckRecordSponsorBinding — is gone
// (NX-01), so the file can no longer decide whether a block is accepted; that removal is
// pinned structurally by test/unit/wiring_callsites_test.go. What these tests pin is the
// loader itself.
//
// FAIL-ON-PRISTINE: every case below is red against the shipped loader —
// TestNX05MalformedLineIsAStartupErrorNotAPanic PANICS it (index out of range on
// sponsorInfo[1]), TestNX05NegativeHeightIsRejected silently loads height 4294967295,
// TestNX05ExistingButUnreadableFileIsAStartupError returns an empty map with no error,
// TestNX05RelativePathResolvesAgainstTheDataDirNotTheCWD loads the WRONG file, and
// TestNX05CRLFAndSurroundingWhitespaceAreTolerated fails hex decoding on the trailing \r.
package state

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
)

// nx05Params builds a Configuration whose sponsors file is the given path (relative paths
// resolve against dataDir first, then the working directory).
func nx05Params(dataDir, sponsorsPath string) *config.Configuration {
	c := &config.Configuration{DataDir: dataDir}
	c.DPoSConfiguration.SponsorsFilePath = sponsorsPath
	return c
}

func nx05Write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("harness: write %s: %v", p, err)
	}
	return p
}

// TestNX05RelativePathResolvesAgainstTheDataDirNotTheCWD is the core determinism claim:
// two nodes with the same data directory, started from different working directories, must
// load the same overrides. Shipped, the process working directory chose the file.
func TestNX05RelativePathResolvesAgainstTheDataDirNotTheCWD(t *testing.T) {
	dataDir := t.TempDir()
	cwdDir := t.TempDir()

	// The data-dir copy is the truth; the CWD copy is the trap.
	nx05Write(t, dataDir, "sponsors", "10,02aaaa\n")
	nx05Write(t, cwdDir, "sponsors", "10,02bbbb\n")

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("harness: getwd: %v", err)
	}
	if err := os.Chdir(cwdDir); err != nil {
		t.Fatalf("harness: chdir: %v", err)
	}
	defer func() { _ = os.Chdir(orig) }()

	got, err := LoadBlockConfirmProposalSponsors(nx05Params(dataDir, "sponsors"))
	if err != nil {
		t.Fatalf("NX-05: loading a valid sponsors file failed: %v", err)
	}
	want, _ := common.HexStringToBytes("02aaaa")
	if !bytes.Equal(got[10], want) {
		t.Fatalf("NX-05 REGRESSION: height 10 resolved to %x, want %x. The process WORKING "+
			"DIRECTORY chose the consensus overrides — two nodes with identical data "+
			"directories launched from different shells load different consensus inputs.",
			got[10], want)
	}

	// And with no data-dir copy the configured (working-directory) path is still honoured,
	// so no existing deployment is broken by the change.
	emptyDataDir := t.TempDir()
	got, err = LoadBlockConfirmProposalSponsors(nx05Params(emptyDataDir, "sponsors"))
	if err != nil {
		t.Fatalf("NX-05: working-directory fallback failed: %v", err)
	}
	want, _ = common.HexStringToBytes("02bbbb")
	if !bytes.Equal(got[10], want) {
		t.Fatalf("NX-05: the working-directory fallback stopped working (got %x want %x) — "+
			"the hardening must not silently drop an operator's existing file", got[10], want)
	}
}

// TestNX05UnsetDataDirStillResolvesAgainstTheNodeDataDirectory. main.go falls back to the
// config.DataDir default when cfg.DataDir is unset, and so must the sponsors lookup —
// otherwise the commonest configuration of all (no explicit DataDir) is the one that keeps
// letting the working directory choose the overrides.
func TestNX05UnsetDataDirStillResolvesAgainstTheNodeDataDirectory(t *testing.T) {
	cwdDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwdDir, config.DataDir), 0o755); err != nil {
		t.Fatalf("harness: mkdir: %v", err)
	}
	nx05Write(t, filepath.Join(cwdDir, config.DataDir), "sponsors", "10,02aaaa\n")
	nx05Write(t, cwdDir, "sponsors", "10,02bbbb\n")

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("harness: getwd: %v", err)
	}
	if err := os.Chdir(cwdDir); err != nil {
		t.Fatalf("harness: chdir: %v", err)
	}
	defer func() { _ = os.Chdir(orig) }()

	got, err := LoadBlockConfirmProposalSponsors(nx05Params("", "sponsors"))
	if err != nil {
		t.Fatalf("NX-05: load with unset DataDir failed: %v", err)
	}
	want, _ := common.HexStringToBytes("02aaaa")
	if !bytes.Equal(got[10], want) {
		t.Fatalf("NX-05 REGRESSION: with DataDir unset the sponsors file resolved to %x, want "+
			"%x — the default data directory %q must be searched before the working directory",
			got[10], want, config.DataDir)
	}
}

// TestNX05AbsolutePathIsHonouredVerbatim — an absolute path is never re-rooted.
func TestNX05AbsolutePathIsHonouredVerbatim(t *testing.T) {
	dir := t.TempDir()
	p := nx05Write(t, dir, "pinned-sponsors", "7,03cccc\n")

	got, err := LoadBlockConfirmProposalSponsors(nx05Params(t.TempDir(), p))
	if err != nil {
		t.Fatalf("NX-05: absolute sponsors path failed: %v", err)
	}
	want, _ := common.HexStringToBytes("03cccc")
	if !bytes.Equal(got[7], want) {
		t.Fatalf("NX-05: absolute path %s not honoured: got %x want %x", p, got[7], want)
	}
}

// TestNX05MalformedLineIsAStartupErrorNotAPanic. The shipped parser split each line on ","
// and read field [1] unconditionally, so one comma-less line — a stray word, a truncated
// write, a pasted header — panicked the node inside NewArbitrators before it ever served.
// Crash-hardening: a panic is not an acceptance decision, so this rides no gate.
func TestNX05MalformedLineIsAStartupErrorNotAPanic(t *testing.T) {
	for _, body := range []string{
		"10\n",                // no comma at all — the panic case
		"10,02aaaa,extra\n",   // too many fields
		"notanumber,02aaaa\n", // unparsable height
		"10,zzzz\n",           // unparsable sponsor hex
	} {
		body := body
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			dir := t.TempDir()
			nx05Write(t, dir, "sponsors", body)

			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("NX-05 REGRESSION: the sponsors loader PANICKED on %q (%v). "+
							"A malformed operator file must refuse startup with a readable "+
							"error, never crash the node.", body, r)
					}
				}()
				_, err = LoadBlockConfirmProposalSponsors(nx05Params(dir, "sponsors"))
			}()

			if err == nil {
				t.Fatalf("NX-05 REGRESSION: %q was accepted. A sponsors file that cannot be "+
					"parsed must fail closed, not load a partial consensus override map.", body)
			}
			if !strings.Contains(err.Error(), "sponsors file") {
				t.Fatalf("NX-05: error %q does not name the sponsors file, so an operator "+
					"cannot act on it", err)
			}
		})
	}
}

// TestNX05NegativeHeightIsRejected. strconv.Atoi("-1") succeeded and uint32(-1) wrapped to
// 4294967295, installing an override at a height no chain will ever reach — silently.
func TestNX05NegativeHeightIsRejected(t *testing.T) {
	dir := t.TempDir()
	nx05Write(t, dir, "sponsors", "-1,02aaaa\n")

	got, err := LoadBlockConfirmProposalSponsors(nx05Params(dir, "sponsors"))
	if err == nil {
		t.Fatalf("NX-05 REGRESSION: a negative height was accepted and wrapped to %v — an "+
			"operator typo becomes an invisible override", reflect.ValueOf(got).MapKeys())
	}
}

// TestNX05DuplicateHeightWithDifferentSponsorsIsRejected. Last-writer-wins over a
// consensus map means the ORDER of lines decides consensus; two operators who sort the
// same file differently get different maps.
func TestNX05DuplicateHeightWithDifferentSponsorsIsRejected(t *testing.T) {
	dir := t.TempDir()
	nx05Write(t, dir, "sponsors", "10,02aaaa\n10,02bbbb\n")

	if _, err := LoadBlockConfirmProposalSponsors(nx05Params(dir, "sponsors")); err == nil {
		t.Fatal("NX-05: a height declared twice with different sponsors was accepted — line " +
			"ORDER would then decide a consensus input")
	}

	// A benign exact duplicate stays acceptable.
	dir2 := t.TempDir()
	nx05Write(t, dir2, "sponsors", "10,02aaaa\n10,02aaaa\n")
	if _, err := LoadBlockConfirmProposalSponsors(nx05Params(dir2, "sponsors")); err != nil {
		t.Fatalf("NX-05: an exact duplicate line must not be an error: %v", err)
	}
}

// TestNX05ExistingButUnreadableFileIsAStartupError. Shipped, ANY os.ReadFile failure was
// reported as "sponsors file not exist!" and the node continued with an empty map — the
// same observable state as a correctly configured node with no file, and a consensus
// difference the operator never sees. A directory at the sponsors path reproduces this
// without depending on file permissions (which are meaningless when running as root).
func TestNX05ExistingButUnreadableFileIsAStartupError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sponsors"), 0o755); err != nil {
		t.Fatalf("harness: mkdir: %v", err)
	}

	_, err := LoadBlockConfirmProposalSponsors(nx05Params(dir, "sponsors"))
	if err == nil {
		t.Fatal("NX-05 REGRESSION: a sponsors path that exists but cannot be read produced a " +
			"silent empty override map instead of refusing to start")
	}
	if !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("NX-05: unexpected error %q", err)
	}
}

// TestNX05AbsentFileIsEmptyAndNotAnError — mainnet's configuration. No sponsors file exists
// under the retained chain's data directory and the mainnet config sets no path, so the
// empty map is correct and must stay a warning rather than a startup refusal.
func TestNX05AbsentFileIsEmptyAndNotAnError(t *testing.T) {
	got, err := LoadBlockConfirmProposalSponsors(nx05Params(t.TempDir(), "sponsors"))
	if err != nil {
		t.Fatalf("NX-05: an absent sponsors file must not be a startup error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("NX-05: an absent sponsors file yielded %d overrides", len(got))
	}
	if got == nil {
		t.Fatal("NX-05: the loader must return an empty map, never nil — callers index it")
	}

	// An empty configured path is equally inert.
	got, err = LoadBlockConfirmProposalSponsors(nx05Params(t.TempDir(), ""))
	if err != nil || len(got) != 0 {
		t.Fatalf("NX-05: empty SponsorsFilePath -> %v overrides, err %v", len(got), err)
	}
}

// TestNX05CRLFAndSurroundingWhitespaceAreTolerated. A file edited on Windows, or with a
// stray space after a comma, must load identically on every node or refuse — never load a
// DIFFERENT map. Shipped, the trailing \r made HexStringToBytes fail and the node refused
// to start, which is at least loud; the space case is the silent one.
func TestNX05CRLFAndSurroundingWhitespaceAreTolerated(t *testing.T) {
	dir := t.TempDir()
	nx05Write(t, dir, "sponsors", "10, 02aaaa\r\n  11,02bbbb  \r\n\r\n")

	got, err := LoadBlockConfirmProposalSponsors(nx05Params(dir, "sponsors"))
	if err != nil {
		t.Fatalf("NX-05: a CRLF/whitespace sponsors file failed to load: %v", err)
	}
	for h, hexSponsor := range map[uint32]string{10: "02aaaa", 11: "02bbbb"} {
		want, _ := common.HexStringToBytes(hexSponsor)
		if !bytes.Equal(got[h], want) {
			t.Fatalf("NX-05: height %d loaded as %x, want %x", h, got[h], want)
		}
	}
	if len(got) != 2 {
		t.Fatalf("NX-05: loaded %d overrides, want 2", len(got))
	}
}

// TestNX01ArbitratorsInterfaceExposesNoSponsorBinding is the compile-time half of the
// NX-01 withdrawal. Re-adding a sponsor-binding method to the Arbitrators interface is the
// first step of re-adding the fork, and it is exactly the step a reviewer would wave
// through. Any future binding must be derived from data the chain commits to, never from
// the locally stored confirm.
func TestNX01ArbitratorsInterfaceExposesNoSponsorBinding(t *testing.T) {
	iface := reflect.TypeOf((*Arbitrators)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		if strings.Contains(name, "RecordSponsorBinding") {
			t.Fatalf("NX-01 REGRESSION: the Arbitrators interface declares %s. F-032's "+
				"block-validity binding was withdrawn because it keyed acceptance on "+
				"lastBlock.Confirm.Proposal.Sponsor — a per-node value nothing commits to, "+
				"which the miner and the validator derived by different rules and which "+
				"honest nodes disagree about after a view change. See "+
				"blockchain/blockvalidator.go CheckBlockContext.", name)
		}
	}
}
