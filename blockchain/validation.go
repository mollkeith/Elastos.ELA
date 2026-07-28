// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"errors"

	"sort"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/contract"
	. "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/crypto"
)

func RunPrograms(data []byte, programHashes []common.Uint168, programs []*Program,
	blockHeight, strictMoneyHeight uint32) error {
	if len(programHashes) != len(programs) {
		return errors.New("the number of data hashes is different with number of programs")
	}

	for i, program := range programs {
		programHash := programHashes[i]
		prefixType := contract.GetPrefixType(programHash)

		// TODO: this implementation will be deprecated
		// Do not restore an ownerHash==codeHash bind on this branch: a PrefixCrossChain
		// custody address is derived from the sidechain genesis hash
		// (contract.CreateCrossChainRedeemScript), not from the arbiter pubkeys, while a
		// legitimate spend supplies program.Code = the arbiter m/n multisig script, so
		// ToCodeHash(arbiterCode) can never equal the genesis-derived ownerHash. Applying
		// the generic bind below to this branch would reject every legitimate
		// WithdrawFromSideChain and ReturnSideChainDeposit, which is a consensus break. The
		// real arbiter authorization lives in the tx-type SpecialContextCheck
		// (withdrawfromsidechain / returnsidechaindeposit) plus the
		// checkTransactionCrossChainUTXO admit-list, so the `continue` is correct.
		//
		// Still open: checkCrossChainSignatures has no `m<1||m>n` guard
		// (VerifyMultisigSignatures treats m<=0 as satisfied), which is an anyone-can-spend
		// on freeze-off paths, masked on mainnet by the freeze/restriction admit-list. A
		// gated fix needs the block height threaded into RunPrograms.
		if prefixType == contract.PrefixCrossChain {
			if contract.IsSchnorr(program.Code) {
				if ok, err := checkSchnorrSignatures(*program, common.Sha256D(data[:]),
					blockHeight, strictMoneyHeight); !ok {
					return errors.New("check schnorr signature failed:" + err.Error())
				}
			} else {
				if err := checkCrossChainSignatures(*program, data,
					blockHeight, strictMoneyHeight); err != nil {
					return err
				}
			}
			continue
		}

		codeHash := common.ToCodeHash(program.Code)
		ownerHash := programHash.ToCodeHash()

		if !ownerHash.IsEqual(*codeHash) {
			return errors.New("the data hashes is different with corresponding program code")
		}
		if prefixType == contract.PrefixStandard || prefixType == contract.PrefixDeposit {
			if contract.IsSchnorr(program.Code) {
				if ok, err := checkSchnorrSignatures(*program, common.Sha256D(data[:]),
					blockHeight, strictMoneyHeight); !ok {
					return errors.New("check schnorr signature failed:" + err.Error())
				}
			} else if contract.IsStandard(program.Code) {
				if err := CheckStandardSignature(*program, data); err != nil {
					return err
				}
			} else if contract.IsMultiSig(program.Code) {
				log.Info("mulitisign deposite")
				if err := crypto.CheckMultiSigSignatures(*program, data); err != nil {
					return err
				}
			} else if blockHeight >= strictMoneyHeight {
				// A Standard/Deposit-prefixed program whose Code hashes to the address
				// (ownerHash==codeHash) but is none of Schnorr/Standard/MultiSig would
				// otherwise fall through with no signature check, making any UTXO parked
				// at such an address anyone-can-spend. Fail closed at and above the gate.
				return errors.New("unknown standard/deposit signature type")
			}
		} else if prefixType == contract.PrefixMultiSig {
			if err := crypto.CheckMultiSigSignatures(*program, data); err != nil {
				return err
			}
		} else {
			return errors.New("unknown signature type")
		}
	}

	return nil
}

func GetTxProgramHashes(tx interfaces.Transaction, references map[*common2.Input]common2.Output) ([]common.Uint168, error) {
	if tx == nil {
		return nil, errors.New("[BaseTransaction],GetProgramHashes transaction is nil")
	}
	hashes := make([]common.Uint168, 0)
	uniqueHashes := make([]common.Uint168, 0)
	// add inputUTXO's transaction
	for _, output := range references {
		programHash := output.ProgramHash
		hashes = append(hashes, programHash)
	}
	for _, attribute := range tx.Attributes() {
		if attribute.Usage == common2.Script {
			dataHash, err := common.Uint168FromBytes(attribute.Data)
			if err != nil {
				return nil, errors.New("[BaseTransaction], GetProgramHashes err")
			}
			hashes = append(hashes, *dataHash)
		}
	}

	//remove duplicated hashes
	unique := make(map[common.Uint168]bool)
	for _, v := range hashes {
		unique[v] = true
	}
	for k := range unique {
		uniqueHashes = append(uniqueHashes, k)
	}
	return uniqueHashes, nil
}

func CheckStandardSignature(program Program, data []byte) error {
	if len(program.Parameter) != crypto.SignatureScriptLength {
		return errors.New("invalid signature length")
	}

	publicKey, err := crypto.DecodePoint(program.Code[1 : len(program.Code)-1])
	if err != nil {
		return err
	}

	return crypto.Verify(*publicKey, data, program.Parameter[1:])
}

func checkSchnorrSignatures(program Program, data [32]byte,
	blockHeight, strictMoneyHeight uint32) (bool, error) {
	publicKey := [33]byte{}
	copy(publicKey[:], program.Code[2:])

	signature := [64]byte{}
	// Reject a malformed Schnorr program whose Parameter is not a full 64-byte
	// signature before slicing; otherwise program.Parameter[:64] panics (slice
	// bounds out of range) on any pre-auth P2P-relayed tx.
	//
	// The two malformed cases are not symmetric and must not be treated alike.
	// Without a length check the code goes straight to
	// copy(signature[:], program.Parameter[:64]). One half is safe to reject
	// everywhere; the other half would be an accept-to-reject flip on retained
	// history and has to be gated.
	//
	// len < 64 stays ungated, because that case could never be accepted, only
	// panicked on. Program.Parameter is produced solely by Program.Deserialize ->
	// common.ReadVarBytes, which for any count at or below maxPreallocBytes (64 KiB,
	// and 64 is far below it) returns make([]byte, count). That gives cap == len, so
	// Parameter[:64] on a shorter Parameter is a true out-of-range slice and not a
	// reslice into spare capacity: it panics. A panic aborts validation, so no block
	// carrying one was ever accepted and no retained block at or below 2,260,450 can
	// contain one. Rejecting therefore cannot change any retained verdict, and it is
	// strictly better than crashing a node on a pre-auth P2P-relayed tx.
	if len(program.Parameter) < 64 {
		return false, errors.New("invalid schnorr signature length")
	}
	// len > 64 MUST be gated, because the base ACCEPTED it. The slice simply
	// took the leading 64 bytes and SchnorrVerify ran normally, so an over-long
	// Parameter whose first 64 bytes are a valid signature was a valid spend.
	// Single-key Schnorr has been live on mainnet since NormalSchnorrStartHeight
	// (1,405,000), so roughly 855,000 retained blocks sit inside the exposure
	// window. Rejecting it ungated would be an accept -> reject flip on retained
	// history. Below the gate we keep the base behaviour byte for byte: take the
	// first 64 bytes and verify. At and above StrictMoneyRangeHeight the trailing
	// bytes are witness malleability with no meaning, so we fail closed.
	if blockHeight >= strictMoneyHeight && len(program.Parameter) != 64 {
		return false, errors.New("invalid schnorr signature length: trailing bytes after the 64 byte signature")
	}
	copy(signature[:], program.Parameter[:64])

	return crypto.SchnorrVerify(publicKey, data, signature)
}

func checkCrossChainSignatures(program Program, data []byte,
	blockHeight, strictMoneyHeight uint32) error {
	code := program.Code
	// Get N parameter
	n := int(code[len(code)-2]) - crypto.PUSH1 + 1
	// Get M parameter
	m := int(code[0]) - crypto.PUSH1 + 1
	// VerifyMultisigSignatures treats m<=0 as trivially satisfied, so an m<1 (or
	// m>n) crosschain redeem script is anyone-can-spend on freeze-off paths.
	// Reject at and above the gate. On mainnet this is masked by the
	// freeze/restriction admit-list, so below-gate validation stays
	// byte-identical.
	if blockHeight >= strictMoneyHeight && (m < 1 || m > n) {
		return errors.New("invalid crosschain multisig m/n")
	}
	publicKeys, err := crypto.ParseCrossChainScript(code)
	if err != nil {
		return err
	}

	return crypto.VerifyMultisigSignatures(m, n, publicKeys, program.Parameter, data)
}

func SortPrograms(programs []*Program) {
	sort.Sort(ByHash(programs))
}

type ByHash []*Program

func (p ByHash) Len() int      { return len(p) }
func (p ByHash) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p ByHash) Less(i, j int) bool {
	hashi := common.ToCodeHash(p[i].Code)
	hashj := common.ToCodeHash(p[j].Code)
	return hashi.Compare(*hashj) < 0
}
