// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"bytes"
	"io"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
)

const (
	InvalidBlockSize int = -1
)

type Header struct {
	Version    uint32
	Previous   common.Uint256
	MerkleRoot common.Uint256
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
	Height     uint32
	AuxPow     auxpow.AuxPow
}

func (header *Header) Serialize(w io.Writer) error {
	err := header.SerializeNoAux(w)
	if err != nil {
		return err
	}

	err = header.AuxPow.Serialize(w)
	if err != nil {
		return err
	}

	// F-128 (write side): the trailing sentinel byte used to be written with
	// both return values discarded, so a writer that failed here emitted a
	// truncated header and still reported success.
	//
	// The read side is deliberately NOT made strict here: Header.Deserialize
	// discards the sentinel with r.Read(make([]byte, 1)), and requiring it
	// would reject inputs that are accepted today on consensus paths -
	// blockchain/txvalidator.go checkDPOSElaIllegalBlockHeaders and
	// ValidateProposalEvidence both deserialize an attacker-supplied header
	// blob out of a transaction payload. Tightening that moves an acceptance
	// decision and therefore needs a height gate.
	if _, err := w.Write([]byte{byte(1)}); err != nil {
		return err
	}

	return nil
}

func (header *Header) Deserialize(r io.Reader) error {
	err := common.ReadElements(r,
		&header.Version,
		&header.Previous,
		&header.MerkleRoot,
		&header.Timestamp,
		&header.Bits,
		&header.Nonce,
		&header.Height,
	)
	if err != nil {
		return err
	}

	// AuxPow
	err = header.AuxPow.Deserialize(r)
	if err != nil {
		return err
	}

	r.Read(make([]byte, 1))

	return nil
}

func (header *Header) SerializeNoAux(w io.Writer) error {
	return common.WriteElements(w,
		header.Version,
		&header.Previous,
		&header.MerkleRoot,
		header.Timestamp,
		header.Bits,
		header.Nonce,
		header.Height,
	)
}

func (header *Header) DeserializeNoAux(r io.Reader) error {
	err := common.ReadElements(r,
		&header.Version,
		&header.Previous,
		&header.MerkleRoot,
		&header.Timestamp,
		&header.Bits,
		&header.Nonce,
		&header.Height,
	)
	if err != nil {
		return err
	}

	return nil
}

func (header *Header) Hash() common.Uint256 {
	buf := new(bytes.Buffer)
	header.SerializeNoAux(buf)
	return common.Hash(buf.Bytes())
}

func (header *Header) HashWithAux() common.Uint256 {
	buf := new(bytes.Buffer)
	header.Serialize(buf)
	return common.Hash(buf.Bytes())
}

func (header *Header) GetSize() int {
	buf := new(bytes.Buffer)
	if err := header.Serialize(buf); err != nil {
		return InvalidBlockSize
	}

	return buf.Len()
}
