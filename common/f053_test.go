// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"bytes"
	"io"
	"runtime"
	"testing"
)

// TestF053ReadVarBytesDoesNotPreallocateDeclaredLength is the fail-on-pristine
// test for F-053. Before the fix ReadVarBytes did make([]byte, count) before
// reading a single byte of payload, so a handful of wire bytes declaring the
// 16MB field maximum (what core/types/common.Attribute.Deserialize passes as
// maxAllowed) forced a 16MB allocation that was immediately discarded.
func TestF053ReadVarBytesDoesNotPreallocateDeclaredLength(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteVarUint(&buf, uint64(MaxVarStringLength)); err != nil {
		t.Fatal(err)
	}
	// Three bytes of actual payload behind a 16MB declared length.
	buf.Write([]byte{0x01, 0x02, 0x03})
	fragment := buf.Bytes()

	if len(fragment) > 16 {
		t.Fatalf("test fragment should be a handful of bytes, got %d", len(fragment))
	}

	const attempts = 4

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	for i := 0; i < attempts; i++ {
		b, err := ReadVarBytes(bytes.NewReader(fragment),
			MaxVarStringLength, "attribute data")
		if err == nil {
			t.Fatal("truncated attribute data should not decode")
		}
		if b != nil {
			t.Fatal("failed decode should not return bytes")
		}
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	// Pristine: attempts * 16MB = 64MB. Fixed: attempts * 64KB = 256KB.
	const budget = 4 << 20
	if allocated > budget {
		t.Fatalf("F-053: %d decode attempts over %d bytes of input allocated "+
			"%d bytes (budget %d) - the declared length is still being "+
			"allocated before the payload is read",
			attempts, len(fragment), allocated, budget)
	}
}

// TestF053ReadVarBytesSemanticsUnchanged pins the behaviour that must NOT move:
// the same bytes decode, and the same errors come back, for fields larger than
// the pre-allocation cap. This passes both before and after the fix - it is the
// guard that the F-053 fix is allocation-strategy only and moves no acceptance
// decision.
func TestF053ReadVarBytesSemanticsUnchanged(t *testing.T) {
	data := make([]byte, 64*1024*2+123)
	for i := range data {
		data[i] = byte(i)
	}

	var full bytes.Buffer
	if err := WriteVarBytes(&full, data); err != nil {
		t.Fatal(err)
	}
	encoded := full.Bytes()

	got, err := ReadVarBytes(bytes.NewReader(encoded),
		uint32(len(data))+1, "big field")
	if err != nil {
		t.Fatalf("well formed large field must still decode: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("large field round trip changed the bytes")
	}

	// One byte short of the declared length -> io.ErrUnexpectedEOF.
	if _, err := ReadVarBytes(bytes.NewReader(encoded[:len(encoded)-1]),
		uint32(len(data))+1, "big field"); err != io.ErrUnexpectedEOF {
		t.Fatalf("partial payload should be io.ErrUnexpectedEOF, got %v", err)
	}

	// Declared length with no payload at all -> io.EOF.
	var header bytes.Buffer
	if err := WriteVarUint(&header, uint64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVarBytes(bytes.NewReader(header.Bytes()),
		uint32(len(data))+1, "big field"); err != io.EOF {
		t.Fatalf("empty payload should be io.EOF, got %v", err)
	}

	// The declared-length ceiling itself is unchanged.
	var over bytes.Buffer
	if err := WriteVarUint(&over, uint64(MaxVarStringLength)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVarBytes(bytes.NewReader(over.Bytes()),
		MaxVarStringLength, "big field"); err == nil {
		t.Fatal("a declared length above maxAllowed must still be rejected")
	}
}
