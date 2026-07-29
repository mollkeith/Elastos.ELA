// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package api

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	// arbiterKeysEnv names the environment variable that overrides the location
	// of the white-box DPoS fixture private key file.
	arbiterKeysEnv = "ELA_SCRIPT_ARBITER_KEYS"

	// defaultArbiterKeysPath is resolved relative to the process working
	// directory. The lua script harness already resolves its own dofile() paths
	// relative to the repository root, so the default matches how the harness is
	// invoked (`ela-cli script -f test/white_box/...`).
	defaultArbiterKeysPath = "test/white_box/arbiter_private_keys.txt"

	// arbiterPrivateKeyHexLen is the hex length of a 32-byte private key.
	arbiterPrivateKeyHexLen = 64
)

var (
	arbiterKeysOnce sync.Once
	arbiterKeys     []string
	arbiterKeysErr  error
)

// arbitratorPrivateKey returns the white-box fixture private key of the arbiter
// at the given index.
//
// F-159: the keys are read from an external fixture file instead of being
// compiled in as a package var, so that no signing key material is embedded in
// the distributed ela-cli binary. The values are unchanged, so the harness
// behaves exactly as before.
func arbitratorPrivateKey(index int) (string, error) {
	keys, err := loadArbiterPrivateKeys()
	if err != nil {
		return "", err
	}
	if index < 0 || index >= len(keys) {
		return "", fmt.Errorf("arbiter index %d out of range [0,%d)", index, len(keys))
	}
	return keys[index], nil
}

// loadArbiterPrivateKeys reads and validates the fixture key file once per
// process.
func loadArbiterPrivateKeys() ([]string, error) {
	arbiterKeysOnce.Do(func() {
		arbiterKeys, arbiterKeysErr = readArbiterPrivateKeys(arbiterKeysPath())
	})
	return arbiterKeys, arbiterKeysErr
}

// arbiterKeysPath returns the fixture key file path, honouring the environment
// override.
func arbiterKeysPath() string {
	if p := strings.TrimSpace(os.Getenv(arbiterKeysEnv)); p != "" {
		return p
	}
	return defaultArbiterKeysPath
}

// readArbiterPrivateKeys parses one 32-byte hex private key per line, skipping
// blank lines and '#' comments.
func readArbiterPrivateKeys(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixture key file %q (set %s to override): %v",
			path, arbiterKeysEnv, err)
	}
	defer file.Close()

	keys := make([]string, 0, len(arbitratorsPublicKeys))
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if len(text) != arbiterPrivateKeyHexLen {
			return nil, fmt.Errorf("%s:%d: expected %d hex chars, got %d",
				path, line, arbiterPrivateKeyHexLen, len(text))
		}
		if _, err := hex.DecodeString(text); err != nil {
			return nil, fmt.Errorf("%s:%d: not hex: %v", path, line, err)
		}
		keys = append(keys, text)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(keys) != len(arbitratorsPublicKeys) {
		return nil, fmt.Errorf("%s: expected %d fixture keys, got %d",
			path, len(arbitratorsPublicKeys), len(keys))
	}
	return keys, nil
}
