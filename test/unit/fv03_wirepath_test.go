// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-03 — fail-on-pristine for the NextTurnDPOSInfo decode-DoS cap.
//
// The proof drives the PRODUCTION WIRE PATH, not the function that was edited:
//
//	p2p.ReadMessage (p2p/message.go:90)
//	  -> createMessage, CmdTx branch (elanet/server.go)
//	    -> peer.CheckAndCreateTxMessage (p2p/peer/peer.go:554)
//	      -> functions.GetTransactionByBytes  (wired exactly as
//	         common/config/settings/settings.go:53 wires it in production)
//	        -> BaseTransaction.Deserialize -> DeserializeUnsigned
//	          -> payload.NextTurnDPOSInfo.DeserializeUnsigned   <-- the three make()s
//
// Everything downstream of the decoder (attributes, inputs, outputs, programs,
// semantic checks, context checks) is irrelevant here: the allocation happens
// before any of it runs, which is exactly why 40 unauthenticated bytes suffice.
//
// TestFV03CmdTxRoutesToCheckAndCreateTxMessage pins the one production routing
// edge this file reproduces rather than imports (createMessage is unexported in
// package elanet), so the behavioural test cannot silently drift away from the
// path it claims to cover.
package unit

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	transaction2 "github.com/elastos/Elastos.ELA/core/transaction"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/p2p"
	peer2 "github.com/elastos/Elastos.ELA/p2p/peer"
)

// fv03CreateMessage is the verbatim CmdTx branch of elanet/server.go's
// createMessage. TestFV03CmdTxRoutesToCheckAndCreateTxMessage asserts the
// production switch still routes CmdTx here.
func fv03CreateMessage(hdr p2p.Header, r net.Conn) (p2p.Message, error) {
	switch hdr.GetCMD() {
	case p2p.CmdTx:
		return peer2.CheckAndCreateTxMessage(hdr, r)
	}
	return nil, p2p.ErrInvalidHeader
}

// fv03AttackBody builds the 16-byte transaction body an unauthenticated peer
// sends: TxVersion09, TxType NextTurnDPOSInfo, payload version 0, a 4-byte
// WorkingHeight, then the CRPublicKeys count varint. Nothing after the count is
// ever read — the make() runs first.
func fv03AttackBody(count uint64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(common2.TxVersion09))
	buf.WriteByte(byte(common2.NextTurnDPOSInfo))
	buf.WriteByte(0x00) // payload version
	var height [4]byte
	binary.LittleEndian.PutUint32(height[:], 0)
	buf.Write(height[:])
	common.WriteVarUint(&buf, count)
	return buf.Bytes()
}

// fv03Deliver frames the body as a real ELA `tx` message and pushes it through
// the production p2p.ReadMessage. It returns the error ReadMessage produced and
// the value recovered from any panic on that goroutine.
func fv03Deliver(t *testing.T, body []byte) (readErr error, recovered interface{}, wireBytes int) {
	t.Helper()

	const magic = uint32(2017001)
	hdr := p2p.BuildHeader(magic, p2p.CmdTx, body)
	hdrBytes, err := hdr.Serialize()
	if err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	frame := append(hdrBytes, body...)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write(frame)
	}()

	done := make(chan struct{})
	go func() {
		defer func() {
			recovered = recover()
			close(done)
		}()
		_, readErr = p2p.ReadMessage(server, magic, time.Second*5, fv03CreateMessage)
	}()
	<-done

	return readErr, recovered, len(frame)
}

func fv03WireFunctions() {
	functions.GetTransactionByTxType = transaction2.GetTransaction
	functions.GetTransactionByBytes = transaction2.GetTransactionByBytes
	functions.CreateTransaction = transaction2.CreateTransaction
	functions.GetTransactionParameters = transaction2.GetTransactionparameters
}

// TestFV03UnauthenticatedTxFrameCannotKillTheDecoder is the fail-on-pristine
// assertion. On the pristine tree the 1<<40 probe reaches
// `make([][]byte, 0, 1<<40)` and the runtime panics with
// "makeslice: cap out of range" on the goroutine that owns the connection —
// which in production is the peer's inbound goroutine, where nothing recovers
// (`grep -rn 'recover()'` returns no hit anywhere in p2p/).
func TestFV03UnauthenticatedTxFrameCannotKillTheDecoder(t *testing.T) {
	fv03WireFunctions()

	// MUTATION-VERIFIED (guards replaced by `if false`, both probes):
	//
	//	fatal error: runtime: out of memory
	//	runtime.sysMapOS(0xc000400000, 0x180000000000)   // 24 TiB
	//	  ... unit.fv03Deliver  test/unit/fv03_wirepath_test.go:103
	//
	// i.e. without the cap this does not merely panic — it is a runtime THROW
	// that recover() cannot catch and that takes the whole test binary (in
	// production, the whole node) down. The suite reports FAIL either way, which
	// is the fail-on-pristine requirement; the recover() in fv03Deliver is the
	// belt-and-braces leg for the smaller "makeslice: cap out of range" variant.
	// That the pristine tree cannot be probed without killing the process is
	// itself the argument for a cap here rather than a panic boundary on the
	// peer goroutine.
	for _, count := range []uint64{uint64(1) << 40, ^uint64(0)} {
		body := fv03AttackBody(count)
		readErr, recovered, wire := fv03Deliver(t, body)

		if recovered != nil {
			t.Fatalf("FV-03 REGRESSION: %d unauthenticated wire bytes PANICKED the "+
				"production p2p read path (count=%#x): %v", wire, count, recovered)
		}
		if readErr == nil {
			t.Fatalf("FV-03 REGRESSION: production p2p read path ACCEPTED a "+
				"NextTurnDPOSInfo payload declaring %#x public keys", count)
		}
		if wire > 64 {
			t.Fatalf("FV-03 harness is not honest: expected a ~40-byte frame, got %d", wire)
		}
		t.Logf("FV-03 ok: count=%#x, %d wire bytes, rejected with: %v", count, wire, readErr)
	}
}

// TestFV03AllThreeKeyListsAreCapped covers the DPOSPublicKeys and
// CompleteCRPublicKeys sites as well, so a fix applied to only the first make()
// still fails. The second and third counts are reached only after the earlier
// lists decode, so each body carries real (empty) predecessors.
func TestFV03AllThreeKeyListsAreCapped(t *testing.T) {
	fv03WireFunctions()

	const huge = uint64(1) << 40

	// site 2: DPOSPublicKeys — CRPublicKeys count 0, then the huge count.
	var b2 bytes.Buffer
	b2.Write(fv03AttackBody(0))
	common.WriteVarUint(&b2, huge)

	// site 3: CompleteCRPublicKeys — payload version 1, both earlier lists empty.
	var b3 bytes.Buffer
	b3.WriteByte(byte(common2.TxVersion09))
	b3.WriteByte(byte(common2.NextTurnDPOSInfo))
	b3.WriteByte(0x01) // NextTurnDPOSInfoVersion2
	var height [4]byte
	binary.LittleEndian.PutUint32(height[:], 0)
	b3.Write(height[:])
	common.WriteVarUint(&b3, 0) // CRPublicKeys
	common.WriteVarUint(&b3, 0) // DPOSPublicKeys
	common.WriteVarUint(&b3, huge)

	for name, body := range map[string][]byte{
		"DPOSPublicKeys":       b2.Bytes(),
		"CompleteCRPublicKeys": b3.Bytes(),
	} {
		readErr, recovered, wire := fv03Deliver(t, body)
		if recovered != nil {
			t.Fatalf("FV-03 REGRESSION (%s): %d wire bytes PANICKED the production "+
				"p2p read path: %v", name, wire, recovered)
		}
		if readErr == nil {
			t.Fatalf("FV-03 REGRESSION (%s): production p2p read path ACCEPTED a "+
				"payload declaring %#x public keys", name, huge)
		}
		t.Logf("FV-03 ok (%s): %d wire bytes, rejected with: %v", name, wire, readErr)
	}
}

// TestFV03HonestPayloadStillDecodes is the below-gate byte-identity half: the
// cap must not reject anything the chain has ever carried. The mainnet-copy
// census over all 2,260,597 records / 41,922 NextTurnDPOSInfo transactions
// measured max(CRPublicKeys)=12, max(DPOSPublicKeys)=36,
// max(CompleteCRPublicKeys)=0; 36+12 keys is reproduced here end to end.
func TestFV03HonestPayloadStillDecodes(t *testing.T) {
	fv03WireFunctions()

	key := make([]byte, 33)
	key[0] = 0x02

	var body bytes.Buffer
	body.WriteByte(byte(common2.TxVersion09))
	body.WriteByte(byte(common2.NextTurnDPOSInfo))
	body.WriteByte(0x00)
	var height [4]byte
	binary.LittleEndian.PutUint32(height[:], 1413543)
	body.Write(height[:])
	common.WriteVarUint(&body, 12) // observed mainnet maximum
	for i := 0; i < 12; i++ {
		common.WriteVarBytes(&body, key)
	}
	common.WriteVarUint(&body, 36) // observed mainnet maximum
	for i := 0; i < 36; i++ {
		common.WriteVarBytes(&body, key)
	}
	common.WriteVarUint(&body, 0) // attributes
	common.WriteVarUint(&body, 0) // inputs
	common.WriteVarUint(&body, 0) // outputs
	binary.Write(&body, binary.LittleEndian, uint32(0))
	common.WriteVarUint(&body, 0) // programs

	readErr, recovered, _ := fv03Deliver(t, body.Bytes())
	if recovered != nil {
		t.Fatalf("FV-03: honest 12+36-key payload panicked: %v", recovered)
	}
	if readErr != nil {
		t.Fatalf("FV-03 OVER-TIGHTENED: the largest NextTurnDPOSInfo mainnet has "+
			"ever carried (12 CR + 36 DPoS keys) was rejected: %v", readErr)
	}
}

// TestFV03CmdTxRoutesToCheckAndCreateTxMessage pins the production routing edge
// that fv03CreateMessage reproduces. If elanet/server.go stops handing CmdTx to
// CheckAndCreateTxMessage, the behavioural test above is covering a path the
// node no longer takes, and this fails loudly instead.
func TestFV03CmdTxRoutesToCheckAndCreateTxMessage(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "elanet/server.go"), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse elanet/server.go: %v", err)
	}

	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "createMessage" {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "CheckAndCreateTxMessage" {
				found = true
			}
			return true
		})
		return false
	})

	if !found {
		t.Fatal("FV-03: elanet/server.go createMessage no longer calls " +
			"CheckAndCreateTxMessage — the FV-03 behavioural test is covering a " +
			"path production does not take")
	}
}
