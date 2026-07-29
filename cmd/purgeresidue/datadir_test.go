package purgeresidue

import (
	"flag"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/urfave/cli"
)

// newDataDirContext builds a cli.Context in which the --datadir flag is DECLARED
// with its production default (cmdcom.DataDirFlag carries Value: config.DataDir)
// but, unless argv names it, is NOT set by the operator. That distinction is the
// whole point: c.String("datadir") cannot tell the two apart, c.IsSet can.
func newDataDirContext(t *testing.T, argv ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("datadir", config.DataDir, "")
	if err := set.Parse(argv); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return cli.NewContext(cli.NewApp(), set, nil)
}

// TestResolveDataDirHonoursConfigWhenFlagUnset pins the FV-18 operator trap that
// the flag default must not shadow the configured DataDir. Pre-fix this returns
// the CWD-relative "elastos/data" for a node whose real store is elsewhere, so the
// offline remedy creates a fresh empty store and reports height 0 -- which on
// restart day reads as a successful rollback rather than a flag mistake.
func TestResolveDataDirHonoursConfigWhenFlagUnset(t *testing.T) {
	cfg := &config.Configuration{DataDir: "/srv/ela-mainnet"}

	got := resolveDataDir(newDataDirContext(t), cfg)

	want := filepath.Join("/srv/ela-mainnet", dataPath)
	if got != want {
		t.Fatalf("configured DataDir was shadowed by the --datadir flag DEFAULT: "+
			"resolveDataDir = %q, want %q (the operator never passed --datadir)", got, want)
	}
}

// TestResolveDataDirExplicitFlagStillWins guards the other direction: an operator
// who does pass --datadir must override config.json. Without this, "fixing" the
// predicate by ignoring the flag entirely would pass the test above.
func TestResolveDataDirExplicitFlagStillWins(t *testing.T) {
	cfg := &config.Configuration{DataDir: "/srv/ela-mainnet"}

	got := resolveDataDir(newDataDirContext(t, "--datadir", "/mnt/rescue"), cfg)

	want := filepath.Join("/mnt/rescue", dataPath)
	if got != want {
		t.Fatalf("explicit --datadir was ignored: resolveDataDir = %q, want %q", got, want)
	}
}

// TestResolveDataDirFallsBackToBuiltinDefault covers the no-config no-flag case,
// which must still land on the built-in default rather than an empty path.
func TestResolveDataDirFallsBackToBuiltinDefault(t *testing.T) {
	got := resolveDataDir(newDataDirContext(t), &config.Configuration{})

	want := filepath.Join(config.DataDir, dataPath)
	if got != want {
		t.Fatalf("resolveDataDir = %q, want built-in default %q", got, want)
	}
}
