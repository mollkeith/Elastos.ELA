// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-24 — release assurance.
//
// FAIL-ON-PRISTINE: every assertion below is false on the tree as shipped at
// canonical 6ee9e5d.
//
//	/go.sum was in .gitignore, so a clean `git archive HEAD` export does NOT build
//	(`missing go.sum entry` for 10+ modules, zero packages compiled) and the existing
//	`git diff --exit-code go.mod` could never see dependency content; the three
//	GitHub actions floated on mutable tags; revive was wget'd, chmod +x'd and executed
//	with no integrity check; GOAMD64 was `?=`, so the environment overrode the pin, and a
//	bare `:=` still left `make GOAMD64=v3 release` overriding it;
//	and NOTHING outside CI compared the toolchain actually in use to the .go-version
//	pin that F-210's float-determinism argument rests on (this build box runs
//	go1.22.10 against a 1.20.14 pin).
//
// NOTE ON SCOPE: this file is the FV-24 leg ONLY. The FV-18 remedy/CLI wiring
// assertions that travelled with it in the refused t4-misc batch are deliberately
// absent — that leg landed independently as B1+B5 (canonical 6ee9e5d) with a
// different, incompatible shape, and its wiring is pinned by
// test/unit/wiring_callsites_test.go.
package unit

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// readRepoFile reads a path relative to the repository root.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := ioutil.ReadFile(filepath.Join(repoRoot(t), rel))
	assert.NoError(t, err, "reading %s", rel)
	return string(b)
}

// TestFV24GoSumIsCommittedAndNotIgnored is the leg that made a clean checkout
// unbuildable.
func TestFV24GoSumIsCommittedAndNotIgnored(t *testing.T) {
	root := repoRoot(t)

	gitignore := readRepoFile(t, ".gitignore")
	for _, line := range strings.Split(gitignore, "\n") {
		trimmed := strings.TrimSpace(line)
		assert.NotEqual(t, "/go.sum", trimmed,
			"FV-24: .gitignore still ignores go.sum -- a clean checkout does not build "+
				"and `git diff --exit-code go.sum` can never see dependency content")
		assert.NotEqual(t, "go.sum", trimmed, "FV-24: .gitignore still ignores go.sum")
	}

	sum, err := ioutil.ReadFile(filepath.Join(root, "go.sum"))
	assert.NoError(t, err, "FV-24: go.sum must be present in the tree")
	assert.NotEmpty(t, strings.TrimSpace(string(sum)), "FV-24: go.sum is empty")

	// PRESENT IN THE WORKING TREE IS NOT THE PROPERTY. The defect was that a CLEAN
	// CHECKOUT does not build, so what has to hold is that git TRACKS the file --
	// a developer with a stale local go.sum and a still-ignoring .gitignore would
	// satisfy every assertion above. Skipped outside a git working tree so the
	// suite still runs from an exported archive.
	if _, serr := os.Stat(filepath.Join(root, ".git")); serr == nil {
		cmd := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "go.sum")
		assert.NoError(t, cmd.Run(),
			"FV-24: go.sum exists but is NOT tracked by git, so a fresh clone still "+
				"produces a checkout that cannot build")
	}

	// Every DIRECT requirement must be pinned in go.sum, or the clean-checkout build
	// fails on exactly the module that is missing. (Indirect requirements are subject
	// to go 1.17+ module-graph pruning and legitimately need no go.sum entry when
	// nothing in the build imports them, so asserting over them would be wrong.)
	goMod := readRepoFile(t, "go.mod")
	req := regexp.MustCompile(`(?m)^\s+([a-z0-9./\-]+\.[a-z]+/[^\s]+)\s+(v[^\s]+)\s*$`)
	seen := 0
	for _, m := range req.FindAllStringSubmatch(goMod, -1) {
		mod, ver := m[1], m[2]
		seen++
		assert.Contains(t, string(sum), mod+" "+ver+" h1:",
			"FV-24: go.sum has no module hash for direct requirement %s %s -- a clean "+
				"checkout fails with `missing go.sum entry` on it", mod, ver)
	}
	assert.Greater(t, seen, 5, "FV-24: go.mod direct require block was not parsed")
}

// TestFV24CIVerifiesTheCommittedDependencySet turns the previously vacuous
// `git diff --exit-code go.mod` into a real check.
func TestFV24CIVerifiesTheCommittedDependencySet(t *testing.T) {
	ci := readRepoFile(t, ".github/workflows/go.yml")
	assert.Contains(t, ci, "git diff --exit-code go.mod go.sum",
		"FV-24: CI must diff go.sum as well as go.mod; with go.sum untracked the "+
			"existing check was vacuous for dependency content")

	// The diff above is necessary but NOT the property. It only says the committed
	// files did not change; it says nothing about whether they are SUFFICIENT, which
	// is the defect FV-24 exists to close. CI must therefore also build with the
	// module graph frozen, which is what turns "a clean checkout builds" from a claim
	// into a step. -mod=readonly has been the Go default since 1.16, but GOFLAGS is
	// written out explicitly here so a future default change cannot quietly relax it.
	assert.Contains(t, ci, "GOFLAGS=-mod=readonly go build ./...",
		"FV-24: CI must build with the module graph frozen, or nothing proves the "+
			"COMMITTED go.sum is sufficient -- only that it did not change")

	// And it must do so before the diff, so a rewrite performed by the build itself
	// is caught rather than hidden.
	build := strings.Index(ci, "GOFLAGS=-mod=readonly go build ./...")
	diff := strings.Index(ci, "git diff --exit-code go.mod go.sum")
	assert.True(t, build >= 0 && diff >= 0 && build < diff,
		"FV-24: the frozen-graph build must run BEFORE the go.mod/go.sum diff")
}

// TestFV24ActionsArePinnedByCommitSHA — a consensus binary must not have build
// inputs that upstream can re-point under a mutable tag.
func TestFV24ActionsArePinnedByCommitSHA(t *testing.T) {
	ci := readRepoFile(t, ".github/workflows/go.yml")
	uses := regexp.MustCompile(`(?m)uses:\s+([^\s]+)`)
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	found := 0
	for _, m := range uses.FindAllStringSubmatch(ci, -1) {
		ref := m[1]
		parts := strings.SplitN(ref, "@", 2)
		assert.Len(t, parts, 2, "FV-24: unpinned action reference %q", ref)
		if len(parts) == 2 {
			found++
			assert.Regexp(t, sha, parts[1],
				"FV-24: action %s is pinned to the MUTABLE ref %q; pin the full commit SHA",
				parts[0], parts[1])
		}
	}
	assert.Equal(t, 3, found, "FV-24: expected the three workflow actions to be pinned")
}

// TestFV24ReviveDownloadIsChecksumVerified — the linter is downloaded, made
// executable and run inside CI; pristine did so with no checksum and no signature.
func TestFV24ReviveDownloadIsChecksumVerified(t *testing.T) {
	ci := readRepoFile(t, ".github/workflows/go.yml")
	assert.Contains(t, ci, "sha256sum -c",
		"FV-24: the revive tarball is unpacked and executed without any integrity check")

	digest := readRepoFile(t, ".github/revive-1.2.1.sha256")
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}\s+revive_1\.2\.1_Linux_x86_64\.tar\.gz`),
		strings.TrimSpace(digest), "FV-24: the committed revive digest is malformed")

	// The digest must be consulted BEFORE the tarball is unpacked and executed.
	unpack := strings.Index(ci, "tar xf revive")
	check := strings.Index(ci, "sha256sum -c")
	assert.True(t, check >= 0 && check < unpack,
		"FV-24: the checksum must be verified before `tar xf`")
}

// TestFV24ToolchainPinIsEnforcedOutsideCI is the leg that most directly weakens
// F-210: .go-version and the CI matrix advertised a pin that nothing compared against
// the compiler actually in use. GOVER was only stamped into ldflags.
func TestFV24ToolchainPinIsEnforcedOutsideCI(t *testing.T) {
	mk := readRepoFile(t, "Makefile")

	assert.Contains(t, mk, "check-toolchain:",
		"FV-24: the Makefile has no target enforcing the .go-version toolchain pin")
	assert.Contains(t, mk, ".go-version",
		"FV-24: the toolchain guard must read the pin from .go-version")
	assert.Contains(t, mk, "go env GOVERSION",
		"FV-24: the toolchain guard must compare against the toolchain actually in use")

	// The guard must gate the targets that produce shipped artifacts, or it is advice.
	for _, target := range []string{"all", "linux", "release", "repro-check"} {
		assert.Regexp(t, regexp.MustCompile(`(?m)^`+target+`:.*check-toolchain`), mk,
			"FV-24: target %q does not depend on check-toolchain, so it can still be "+
				"built with an unpinned toolchain", target)
	}

	// `?=` yields to the ENVIRONMENT, so `GOAMD64=v3 make release` silently
	// retargeted the very pin the block exists to hold.
	assert.NotRegexp(t, regexp.MustCompile(`(?m)^GOAMD64 \?=`), mk,
		"FV-24: GOAMD64 must not be pinned with ?= -- the environment overrides it")

	// A bare `:=` is NOT enough and the first shape of this fix wrongly claimed it
	// was. MEASURED with GNU Make 4.3 on this tree: `GOAMD64 := v1` does hold against
	// the environment, but `make GOAMD64=v3 release` still resolves v3 and exports v3
	// into the recipe, because a command-line assignment overrides every ordinary
	// makefile assignment whatever its flavour. Only an `override` directive wins.
	assert.NotRegexp(t, regexp.MustCompile(`(?m)^GOAMD64 :=`), mk,
		"FV-24: a bare `GOAMD64 :=` still yields to `make GOAMD64=... release`; the "+
			"pin must be declared with an `override` directive")
	assert.Regexp(t, regexp.MustCompile(`(?m)^override GOAMD64 :=`), mk,
		"FV-24: GOAMD64 must be pinned with `override ... :=`")

	// The pin file itself must exist and be a bare version, since the guard string-
	// compares it against `go env GOVERSION` with the leading "go" stripped.
	pin := strings.TrimSpace(readRepoFile(t, ".go-version"))
	assert.Regexp(t, regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`), pin,
		"FV-24: .go-version must hold a bare toolchain version for the guard to compare")
}

// TestFV24GOAMD64PinResistsOverride executes the pin rather than reading it.
//
// The static assertion above can only see the SHAPE of the assignment, and this
// leg shipped once already with a shape that was documented as blocking a
// command-line override and did not. So the real make is run, with GOAMD64 pushed
// in from both directions, and the value it resolves -- and the value it exports
// into a recipe, which is what `make release` actually hands to the compiler -- is
// asserted to still be the pin.
//
// FAIL-ON-PRISTINE: with `GOAMD64 := v1` (no `override`) the command-line arm
// below reports v3 and this test is RED; with `?=` the environment arm is RED too.
func TestFV24GOAMD64PinResistsOverride(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available on this runner")
	}

	// A throwaway target injected with --eval, so nothing is built and no recipe in
	// the real Makefile runs. Reports BOTH the make-level value and the value the
	// recipe's environment sees, because `export GOAMD64` is what reaches the
	// compiler and an override that stops at the make variable would be useless.
	const probe = "fv24goamd64probe: ; @echo RESOLVED=$(GOAMD64) EXPORTED=$$GOAMD64"

	run := func(env []string, args ...string) string {
		cmd := exec.Command("make", append([]string{"-C", root,
			"--eval=" + probe, "fv24goamd64probe"}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running the GOAMD64 probe (%v %v): %v\n%s", env, args, err, out)
		}
		return string(out)
	}

	if _, err := exec.Command("make", "-C", root,
		"--eval="+probe, "fv24goamd64probe").CombinedOutput(); err != nil {
		t.Skipf("this make does not support --eval: %v", err)
	}

	baseline := run(nil)
	assert.Contains(t, baseline, "RESOLVED=v1",
		"FV-24: the unmolested build does not resolve the pinned GOAMD64: %s", baseline)
	assert.Contains(t, baseline, "EXPORTED=v1",
		"FV-24: GOAMD64 is not exported to recipes: %s", baseline)

	fromEnv := run([]string{"GOAMD64=v3"})
	assert.Contains(t, fromEnv, "RESOLVED=v1",
		"FV-24: `GOAMD64=v3 make` overrode the pin (this is what `?=` did): %s", fromEnv)
	assert.Contains(t, fromEnv, "EXPORTED=v1",
		"FV-24: `GOAMD64=v3 make` reached the compiler environment: %s", fromEnv)

	fromCmdLine := run(nil, "GOAMD64=v3")
	assert.Contains(t, fromCmdLine, "RESOLVED=v1",
		"FV-24: `make GOAMD64=v3` overrode the pin -- a bare `:=` does NOT block a "+
			"command-line assignment, only an `override` directive does: %s", fromCmdLine)
	assert.Contains(t, fromCmdLine, "EXPORTED=v1",
		"FV-24: `make GOAMD64=v3` reached the compiler environment: %s", fromCmdLine)
}

// TestFV24ToolchainGuardActuallyFires runs the real Makefile target rather than
// reading it. A guard that is present, wired into every release target and WRONG is
// exactly the failure class FV-25 exists to catch, so the guard is executed here in
// BOTH directions: it must exit non-zero when the toolchain does not match the pin,
// and it must exit zero when it is told the pin is whatever the toolchain reports.
//
// No pinned toolchain is needed on the runner: the pinned value is injected on the
// make command line, which is how the shell fragment sees it either way.
func TestFV24ToolchainGuardActuallyFires(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available on this runner")
	}

	actual, err := exec.Command("go", "env", "GOVERSION").Output()
	assert.NoError(t, err, "FV-24: cannot read the toolchain version")
	running := strings.TrimPrefix(strings.TrimSpace(string(actual)), "go")

	run := func(pin string, extra ...string) (string, int) {
		args := append([]string{"-C", root, "check-toolchain",
			"GOVERSION_PINNED=" + pin}, extra...)
		out, err := exec.Command("make", args...).CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running make check-toolchain: %v", err)
		}
		return string(out), code
	}

	// MISMATCH: must refuse, loudly and with a non-zero status.
	out, code := run(running + "-not-this-one")
	assert.NotEqual(t, 0, code,
		"FV-24: check-toolchain exited 0 on a toolchain that does not match the pin; "+
			"the guard is inert and release artifacts can still be built unpinned. Output: %s", out)
	assert.Contains(t, out, "TOOLCHAIN PIN VIOLATION",
		"FV-24: the guard must say which pin was violated")

	// MATCH: must not block a correctly pinned build.
	out, code = run(running)
	assert.Equal(t, 0, code,
		"FV-24: check-toolchain refused a toolchain that DOES match the pin: %s", out)

	// The documented escape hatch must warn rather than pass silently.
	out, code = run(running+"-not-this-one", "GOVERSION_CHECK=off")
	assert.Equal(t, 0, code, "FV-24: GOVERSION_CHECK=off must not fail the build: %s", out)
	assert.Contains(t, out, "toolchain pin check DISABLED",
		"FV-24: disabling the pin check must warn that the binary is not shippable")
}
