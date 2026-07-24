// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// repoRoot walks up from the test working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	assert.NoError(t, err)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root (no go.mod found)")
	return ""
}

// walkGoSources visits every non-test, non-vendor .go file under root/rel.
func walkGoSources(t *testing.T, root, rel string, visit func(path string)) {
	t.Helper()
	err := filepath.Walk(filepath.Join(root, rel), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", ".git", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The tree carries tracked AppleDouble resource forks (._*.go); they are
		// binary and are never compiled.
		if strings.HasPrefix(info.Name(), "._") {
			return nil
		}
		visit(path)
		return nil
	})
	assert.NoError(t, err)
}

// isFmtPrint reports whether the call is one of the fmt print-to-stdout helpers.
func isFmtPrint(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "fmt" {
		return false
	}
	switch sel.Sel.Name {
	case "Print", "Printf", "Println":
		return true
	}
	return false
}

// secretIdent matches identifiers that carry, or transitively render, key
// material: the raw hex private-key strings and the wallet account structs
// (account.Account.PrivateKey / account.SchnorAccount.PrivateKeys are printed
// verbatim by the %v verb).
var secretIdent = regexp.MustCompile(`(?i)(priv|mnemonic|passwd|password)`)

func isSecretIdentName(name string) bool {
	if secretIdent.MatchString(name) {
		return true
	}
	switch name {
	case "account", "acc", "sa":
		return true
	}
	return false
}

// TestF158NoKeyMaterialPrintsInScriptAPI proves F-158.
//
// The CRC helper constructors in cmd/script/api echoed their raw hex private
// key arguments to stdout, and dumped the unlocked wallet account struct with
// %+v (account.Account embeds PrivateKey, account.SchnorAccount embeds
// PrivateKeys), so operating the CRC scripts wrote signing keys into shell
// history, CI logs and any captured stdout. This guard fails on the pristine
// tree at cmd/script/api/payloadtype.go and cmd/script/api/accounttype.go.
func TestF158NoKeyMaterialPrintsInScriptAPI(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var offenders []string

	walkGoSources(t, root, filepath.Join("cmd", "script", "api"), func(path string) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isFmtPrint(call) {
				return true
			}
			for _, arg := range call.Args {
				switch a := arg.(type) {
				case *ast.Ident:
					// A bare variable: printed verbatim.
					if isSecretIdentName(a.Name) {
						offenders = append(offenders, positionOf(fset, arg)+": "+a.Name)
					}
				case *ast.SelectorExpr:
					// A field selector such as x.PrivateKey.
					if secretIdent.MatchString(a.Sel.Name) {
						offenders = append(offenders, positionOf(fset, arg)+": ."+a.Sel.Name)
					}
				}
			}
			return true
		})
	})

	assert.Empty(t, offenders,
		"F-158: cmd/script/api must not print private key material to stdout: %v", offenders)
}

func positionOf(fset *token.FileSet, n ast.Node) string {
	p := fset.Position(n.Pos())
	return p.Filename + ":" + strconv.Itoa(p.Line)
}

// fixtureKeyFile is the external file the white-box arbiter fixture keys were
// moved to by the F-159 fix.
const fixtureKeyFile = "test/white_box/arbiter_private_keys.txt"

// TestF159NoFixtureKeysCompiledIn proves F-159.
//
// Six 32-byte arbiter signing keys were declared as a package var in
// cmd/script/api/arbitrators.go, i.e. compiled into every distributed ela-cli
// build. They now live in an external fixture file that the harness reads at
// run time, so no key bytes are linked into the binary. This guard fails on the
// pristine tree.
func TestF159NoFixtureKeysCompiledIn(t *testing.T) {
	root := repoRoot(t)

	keys := readFixtureKeys(t, filepath.Join(root, fixtureKeyFile))
	assert.Equal(t, 6, len(keys), "the fixture file must still carry all six keys")

	var offenders []string
	walkGoSources(t, root, ".", func(path string) {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(data)
		for _, k := range keys {
			if strings.Contains(body, k) {
				offenders = append(offenders, path)
				break
			}
		}
	})
	assert.Empty(t, offenders,
		"F-159: fixture arbiter private keys must not be compiled into shipped "+
			"(non-test) Go sources: %v", offenders)

	// Generic regression rule: no non-test source may declare a 64-hex literal
	// under a "private"-ish name.
	hex64 := regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	fset := token.NewFileSet()
	var declared []string
	walkGoSources(t, root, ".", func(path string) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return // generated or build-tagged files are not our concern here
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			named := false
			for _, name := range spec.Names {
				if secretIdent.MatchString(name.Name) {
					named = true
				}
			}
			if !named {
				return true
			}
			ast.Inspect(spec, func(m ast.Node) bool {
				lit, ok := m.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err == nil && hex64.MatchString(v) {
					declared = append(declared, positionOf(fset, lit))
				}
				return true
			})
			return true
		})
	})
	assert.Empty(t, declared,
		"F-159: no shipped source may declare a 32-byte hex key literal under a "+
			"private-key name: %v", declared)
}

func readFixtureKeys(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	assert.NoError(t, err)
	if err != nil {
		return nil
	}
	defer f.Close()

	var keys []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	assert.NoError(t, s.Err())
	return keys
}

// TestF197NoDebugPrintsInServers proves F-197.
//
// servers/interfaces.go:875 held the only fmt.Println in the whole servers/
// tree — a leftover `fmt.Println("addr", addr)` in the DposV2 branch of
// GetUsedVoteRight that echoed the caller's stake address on every RPC hit.
// This guard fails on the pristine tree.
func TestF197NoDebugPrintsInServers(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var offenders []string

	walkGoSources(t, root, "servers", func(path string) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isFmtPrint(call) {
				offenders = append(offenders, positionOf(fset, call))
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok &&
				(id.Name == "print" || id.Name == "println") && id.Obj == nil {
				offenders = append(offenders, positionOf(fset, call))
			}
			return true
		})
	})

	assert.Empty(t, offenders,
		"F-197: the RPC server tree must log through the log package, not stdout: %v",
		offenders)
}

// TestF210BuildDeterminismPins proves F-210.
//
// go.mod declares only `go 1.20` and CI pinned only the MINOR version, with no
// GOARCH/GOAMD64 pin, no -trimpath and no reproducible-build check. Pinning the
// toolchain patch level and the target architecture is the only available
// mitigation for the float-determinism class (FMA contraction is
// architecture-dependent and cannot be fixed in Go source). This guard fails on
// the pristine tree, which has no .go-version at all.
func TestF210BuildDeterminismPins(t *testing.T) {
	root := repoRoot(t)

	// 1. exact toolchain patch pin, consistent with the go.mod language version
	goVersion, err := ioutil.ReadFile(filepath.Join(root, ".go-version"))
	assert.NoError(t, err, "F-210: .go-version must pin the exact toolchain patch level")
	pinned := strings.TrimSpace(string(goVersion))
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, pinned,
		"F-210: .go-version must be an exact x.y.z patch pin, got %q", pinned)

	goMod, err := ioutil.ReadFile(filepath.Join(root, "go.mod"))
	assert.NoError(t, err)
	lang := regexp.MustCompile(`(?m)^go (\d+\.\d+)$`).FindStringSubmatch(string(goMod))
	assert.NotNil(t, lang, "go.mod must declare a go directive")
	if lang != nil && pinned != "" {
		assert.True(t, strings.HasPrefix(pinned, lang[1]+"."),
			"F-210: .go-version (%s) must match the go.mod language version (%s)",
			pinned, lang[1])
	}

	// 2. CI must consume the pin and must not mutate the module graph mid-build
	ci, err := ioutil.ReadFile(filepath.Join(root, ".github", "workflows", "go.yml"))
	assert.NoError(t, err)
	ciText := string(ci)
	assert.True(t,
		strings.Contains(ciText, "go-version-file") ||
			regexp.MustCompile(`go: \["\d+\.\d+\.\d+"\]`).MatchString(ciText),
		"F-210: CI must pin the exact Go patch version, not just the minor")
	assert.NotContains(t, ciText, "go mod tidy",
		"F-210: CI must not rewrite go.mod/go.sum during a build")

	// 3. the release build must pin the architecture and be checkable
	mk, err := ioutil.ReadFile(filepath.Join(root, "Makefile"))
	assert.NoError(t, err)
	mkText := string(mk)
	for _, want := range []string{"GOAMD64", "-trimpath", "repro-check:"} {
		assert.Contains(t, mkText, want,
			"F-210: the Makefile must carry the reproducible-build pin %q", want)
	}
}
