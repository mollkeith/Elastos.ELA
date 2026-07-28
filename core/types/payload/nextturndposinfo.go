package payload

import (
	"bytes"
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/crypto"
)

const NextTurnDPOSInfoVersion byte = 0x00
const NextTurnDPOSInfoVersion2 byte = 0x01

// MaxNextTurnDPOSInfoPublicKeys bounds each of the three public-key slices at
// decode time (DoS ceiling, the same shape as MaxDPoSIllegalSigners and
// MaxSidechainIllegalSigns).
//
// Without it DeserializeUnsigned passes all three wire varints straight to
// make([][]byte, 0, len) as capacity, so the whole allocation happens before a
// single declared element is read. common.ReadVarUint takes no max-length
// argument (its second parameter is pver and is never read), so no caller can
// bound it, and the smallest legal 0xff-form value is 2^32: 2^32 * 24 bytes of
// slice header = 103 GiB. Reachable pre-handshake, because peer.readRemoteVersionMsg
// fully decodes the first message of a connection before checking that it is a
// Version message, and CheckAndCreateTxMessage bounds only the frame length
// (8 MiB), so a 40-byte unauthenticated frame reaches this decoder. The 2^32
// variant is a runtime throw (out of memory) which recover() cannot catch,
// hence a cap here rather than a panic boundary on the peer goroutine.
//
// Ceiling justification, measured over all 2,260,597 retained records and the
// 41,922 NextTurnDPOSInfo transactions in them: max len(CRPublicKeys) = 12
// (height 751431), max len(DPOSPublicKeys) = 36 (height 1413543), max
// len(CompleteCRPublicKeys) = 0 (never populated in all history). 1024 is 28x
// the largest value this payload has ever carried, so no retained block can
// decode differently. Ungated: today the decode does not reject the message, it
// kills the process, and a dead process has made no acceptance decision.
const MaxNextTurnDPOSInfoPublicKeys = 1024

type NextTurnDPOSInfo struct {
	WorkingHeight        uint32
	CRPublicKeys         [][]byte
	DPOSPublicKeys       [][]byte
	CompleteCRPublicKeys [][]byte

	hash *common.Uint256
}

func (n *NextTurnDPOSInfo) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := n.Serialize(buf, version); err != nil {
		return []byte{0}
	}
	return buf.Bytes()
}

func (n *NextTurnDPOSInfo) Serialize(w io.Writer, version byte) error {
	err := n.SerializeUnsigned(w, version)
	if err != nil {
		return err
	}

	return nil
}

func (n *NextTurnDPOSInfo) SerializeUnsigned(w io.Writer, version byte) error {

	if err := common.WriteUint32(w, n.WorkingHeight); err != nil {
		return err
	}
	if err := common.WriteVarUint(w, uint64(len(n.CRPublicKeys))); err != nil {
		return err
	}

	for _, v := range n.CRPublicKeys {
		if err := common.WriteVarBytes(w, v); err != nil {
			return err
		}
	}

	if err := common.WriteVarUint(w, uint64(len(n.DPOSPublicKeys))); err != nil {
		return err
	}

	for _, v := range n.DPOSPublicKeys {
		if err := common.WriteVarBytes(w, v); err != nil {
			return err
		}
	}

	if version >= NextTurnDPOSInfoVersion2 {
		if err := common.WriteVarUint(w, uint64(len(n.CompleteCRPublicKeys))); err != nil {
			return err
		}

		for _, v := range n.CompleteCRPublicKeys {
			if err := common.WriteVarBytes(w, v); err != nil {
				return err
			}
		}
	}

	return nil
}

func (n *NextTurnDPOSInfo) Deserialize(r io.Reader, version byte) error {
	err := n.DeserializeUnsigned(r, version)
	if err != nil {
		return err
	}
	return nil
}

func (n *NextTurnDPOSInfo) DeserializeUnsigned(r io.Reader, version byte) error {
	var err error
	var len uint64

	var workingHeight uint32
	if workingHeight, err = common.ReadUint32(r); err != nil {
		return err
	}
	n.WorkingHeight = workingHeight

	if len, err = common.ReadVarUint(r, 0); err != nil {
		return err
	}
	// Cap the count before allocating.
	if len > MaxNextTurnDPOSInfoPublicKeys {
		return errors.New("next turn dpos info cr public key count exceeds maximum")
	}

	n.CRPublicKeys = make([][]byte, 0, len)
	for i := uint64(0); i < len; i++ {
		var CRPublickey []byte
		if CRPublickey, err = common.ReadVarBytes(r, crypto.COMPRESSEDLEN,
			"cr public key"); err != nil {
			return err
		}
		n.CRPublicKeys = append(n.CRPublicKeys, CRPublickey)
	}

	if len, err = common.ReadVarUint(r, 0); err != nil {
		return err
	}
	// Cap the count before allocating.
	if len > MaxNextTurnDPOSInfoPublicKeys {
		return errors.New("next turn dpos info dpos public key count exceeds maximum")
	}

	n.DPOSPublicKeys = make([][]byte, 0, len)
	for i := uint64(0); i < len; i++ {
		var DPOSPublicKey []byte
		if DPOSPublicKey, err = common.ReadVarBytes(r, crypto.COMPRESSEDLEN,
			"dpos public key"); err != nil {
			return err
		}
		n.DPOSPublicKeys = append(n.DPOSPublicKeys, DPOSPublicKey)
	}

	if version >= NextTurnDPOSInfoVersion2 {
		if len, err = common.ReadVarUint(r, 0); err != nil {
			return err
		}
		// Cap the count before allocating.
		if len > MaxNextTurnDPOSInfoPublicKeys {
			return errors.New("next turn dpos info complete cr public key count exceeds maximum")
		}
		n.CompleteCRPublicKeys = make([][]byte, 0, len)
		for i := uint64(0); i < len; i++ {
			var publicKey []byte
			if publicKey, err = common.ReadVarBytes(r, crypto.COMPRESSEDLEN,
				"complete crcs"); err != nil {
				return err
			}
			n.CompleteCRPublicKeys = append(n.CompleteCRPublicKeys, publicKey)
		}
	}

	return nil
}

func (n *NextTurnDPOSInfo) Hash() common.Uint256 {
	if n.hash == nil {
		buf := new(bytes.Buffer)
		n.SerializeUnsigned(buf, NextTurnDPOSInfoVersion)
		hash := common.Hash(buf.Bytes())
		n.hash = &hash
	}
	return *n.hash
}
