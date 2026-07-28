// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type NFTDestroyTransactionFromSideChain struct {
	BaseTransaction
}

func (t *NFTDestroyTransactionFromSideChain) CheckTransactionInput() error {
	if len(t.Inputs()) != 0 {
		return errors.New("no cost transactions must has no input")
	}
	return nil
}

func (t *NFTDestroyTransactionFromSideChain) CheckTransactionOutput() error {
	if len(t.Outputs()) != 0 {
		return errors.New("no cost transactions should have no output")
	}
	return nil
}

func (t *NFTDestroyTransactionFromSideChain) CheckAttributeProgram() error {
	if len(t.Programs()) != 1 || len(t.Attributes()) != 1 {
		return errors.New("zero cost tx should have one programs and one attributes")
	}

	// Check attributes
	for _, attr := range t.Attributes() {
		if !common2.IsValidAttributeType(attr.Usage) {
			return fmt.Errorf("invalid attribute usage %v", attr.Usage)
		}
	}

	// Check programs
	if len(t.Programs()) == 0 {
		return fmt.Errorf("no programs found in transaction")
	}
	for _, p := range t.Programs() {
		if p.Code == nil {
			return fmt.Errorf("invalid program code nil")
		}
		if len(p.Code) < program.MinProgramCodeSize {
			return fmt.Errorf("invalid program code size")
		}
		if p.Parameter == nil {
			return fmt.Errorf("invalid program parameter nil")
		}
	}
	return nil
}

func (t *NFTDestroyTransactionFromSideChain) CheckTransactionPayload() error {
	_, ok := t.Payload().(*payload.NFTDestroyFromSideChain)
	if !ok {
		return errors.New("Invalid NFTDestroyFromSideChain payload type")
	}

	return nil
}

func (t *NFTDestroyTransactionFromSideChain) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config
	if blockHeight < chainParams.DPoSConfiguration.NFTStartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before NFTStartHeight", t.TxType().Name()))
	}
	return nil
}

func (t *NFTDestroyTransactionFromSideChain) IsAllowedInPOWConsensus() bool {
	return false
}

func (t *NFTDestroyTransactionFromSideChain) SpecialContextCheck() (elaerr.ELAError, bool) {
	nftDestroyPayload, ok := t.Payload().(*payload.NFTDestroyFromSideChain)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}
	// IDs and OwnerStakeAddresses are two independently-counted slices; the apply
	// path (processNFTDestroyFromSideChain, state.go:2895/2961) indexes
	// OwnerStakeAddresses[i] over the IDs loop, so a length mismatch is accepted here
	// then panics (index out of range) on ProcessBlock, halting consensus. Reject the
	// mismatch. Gated at the coordinated-upgrade height for replay-safety; no
	// mismatched NFTDestroy exists in history, since one would have halted every node
	// before tip 2260595.
	if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight &&
		len(nftDestroyPayload.IDs) != len(nftDestroyPayload.OwnerStakeAddresses) {
		return elaerr.Simple(elaerr.ErrTxPayload,
			errors.New("NFTDestroy IDs and OwnerStakeAddresses length mismatch")), true
	}
	// Reject duplicate NFT IDs within one destroy tx. ExistNFTID/CanNFTDestroy are
	// read-only during validation, so a repeated ID passes both and double-applies the
	// destroy on ProcessBlock. Gated at StrictMoneyRangeHeight like the length and
	// genesis-binding checks, so below-gate replay is byte-identical (no arbiter-signed
	// dup-ID NFTDestroy exists in retained history).
	if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
		seen := make(map[common.Uint256]struct{}, len(nftDestroyPayload.IDs))
		for _, id := range nftDestroyPayload.IDs {
			if _, dup := seen[id]; dup {
				return elaerr.Simple(elaerr.ErrTxPayload,
					errors.New("duplicate NFT id in NFTDestroy payload")), true
			}
			seen[id] = struct{}{}
		}
		// Reject an NFTDestroy whose OwnerStakeAddresses name any of its own NFTs'
		// stake addresses. That cross-key aliasing makes the DPoSV2RewardInfo forward
		// closures compose while both reverts subtract pre-block captures, misallocating
		// claimable reward on a reorg (state.go processNFTDestroyFromSideChain). A
		// legitimate new owner is a user stake address, never a derived NFT stake address,
		// so this rejects only the attack.
		nftStakeSet := make(map[common.Uint168]struct{}, len(nftDestroyPayload.IDs))
		for _, id := range nftDestroyPayload.IDs {
			ct, err := contract.CreateStakeContractByCode(id.Bytes())
			if err != nil {
				return elaerr.Simple(elaerr.ErrTxPayload, err), true
			}
			nftStakeSet[*ct.ToProgramHash()] = struct{}{}
		}
		for _, owner := range nftDestroyPayload.OwnerStakeAddresses {
			if _, clash := nftStakeSet[owner]; clash {
				return elaerr.Simple(elaerr.ErrTxPayload,
					errors.New("NFTDestroy owner stake address aliases an NFT stake address in the same tx")), true
			}
		}
	}
	state := t.parameters.BlockChain.GetState()

	// check if the NFT exist
	for _, id := range nftDestroyPayload.IDs {
		if ok := state.ExistNFTID(id); !ok {
			log.Warnf("the NFT is not exist, id:%s", id)
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("the NFT is not exist")), true
		}
	}
	canDestroyIDs := state.CanNFTDestroy(nftDestroyPayload.IDs)
	if len(canDestroyIDs) != len(nftDestroyPayload.IDs) {
		return elaerr.Simple(elaerr.ErrTxPayload,
			errors.New(" NFT can not destroy")), true
	}

	// Bind each destroyed NFT to the sidechain it was created on (see
	// checkNFTDestroyGenesisBinding). Gated at StrictMoneyRangeHeight, so below-gate
	// replay is byte-identical.
	if err := checkNFTDestroyGenesisBinding(nftDestroyPayload.IDs,
		nftDestroyPayload.GenesisBlockHash, state.GetNFTGenesisBlockHash,
		t.parameters.BlockHeight, t.parameters.Config.StrictMoneyRangeHeight); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	err := t.checkNFTDestroyTransactionFromSideChain()
	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}
	return nil, true
}

func (t *NFTDestroyTransactionFromSideChain) checkNFTDestroyTransactionFromSideChain() error {
	buf := new(bytes.Buffer)
	t.SerializeUnsigned(buf)
	height := t.parameters.BlockHeight
	for _, p := range t.Programs() {
		publicKeys, m, n, err := crypto.ParseCrossChainScriptV1(p.Code)
		if err != nil {
			return err
		}
		var arbiters []*state.ArbiterInfo
		var minCount uint32
		if height >= t.parameters.Config.DPoSConfiguration.DPOSNodeCrossChainHeight {
			arbiters = blockchain.DefaultLedger.Arbitrators.GetArbitrators()
			minCount = uint32(t.parameters.Config.DPoSConfiguration.NormalArbitratorsCount) + 1
		} else {
			arbiters = blockchain.DefaultLedger.Arbitrators.GetCRCArbiters()
			minCount = t.parameters.Config.CRConfiguration.CRAgreementCount
		}
		var arbitersCount int
		for _, c := range arbiters {
			if !c.IsNormal {
				continue
			}
			arbitersCount++
		}
		if n != arbitersCount {
			return errors.New("invalid arbiters total count in code")
		}
		if m < int(minCount) {
			return errors.New("invalid arbiters sign count in code")
		}
		if err := checkCrossChainArbitrators(publicKeys); err != nil {
			return err
		}
		if err := checkCrossChainSignatures(*p, buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// checkNFTDestroyGenesisBinding verifies that each destroyed NFT's recorded origin
// sidechain genesis (NFTInfo.GenesisBlockHash, set at CreateNFT) matches the destroy
// payload's GenesisBlockHash, at/above the gate. NFTDestroyFromSideChain otherwise
// carries an unvalidated GenesisBlockHash, so an arbiter-signed destroy could name any
// sidechain genesis. genesisOf is injected (state.GetNFTGenesisBlockHash) for
// testability.
//
// Gate height, open point: unlike the length-mismatch check, whose absence from history
// is provable because a mismatch crashes, this rule is silent-accept, so its absence in
// the re-derived [2260451,2260595] band cannot be shown by scanning. It is safe under
// the mine-new rollback, where corrupt blocks are discarded rather than replayed. If any
// node re-derives by replaying historical blocks, confirm absence in that band or move
// this to a fresh dormant height above the resume tip.
func checkNFTDestroyGenesisBinding(ids []common.Uint256, payloadGenesis common.Uint256,
	genesisOf func(common.Uint256) (common.Uint256, error), height, gate uint32) error {
	if height < gate {
		return nil
	}
	for _, id := range ids {
		genesis, err := genesisOf(id)
		if err != nil {
			return err
		}
		if !genesis.IsEqual(payloadGenesis) {
			return errors.New("NFTDestroy genesis block hash does not match the NFT origin sidechain")
		}
	}
	return nil
}

func checkCrossChainSignatures(program program.Program, data []byte) error {
	code := program.Code
	// Get N parameter
	n := int(code[len(code)-2]) - crypto.PUSH1 + 1
	// Get M parameter
	m := int(code[0]) - crypto.PUSH1 + 1
	publicKeys, err := crypto.ParseCrossChainScript(code)
	if err != nil {
		return err
	}

	return verifyMultisigSignatures(m, n, publicKeys, program.Parameter, data)
}

func verifyMultisigSignatures(m, n int, publicKeys [][]byte, signatures, data []byte) error {
	if len(publicKeys) != n {
		return errors.New("invalid multi sign public key script count")
	}
	if len(signatures)%crypto.SignatureScriptLength != 0 {
		return errors.New("invalid multi sign signatures, length not match")
	}
	if len(signatures)/crypto.SignatureScriptLength < m {
		return errors.New("invalid signatures, not enough signatures")
	}
	if len(signatures)/crypto.SignatureScriptLength > n {
		return errors.New("invalid signatures, too many signatures")
	}

	var verified = make(map[common.Uint256]struct{})
	for i := 0; i < len(signatures); i += crypto.SignatureScriptLength {
		// Remove length byte
		sign := signatures[i : i+crypto.SignatureScriptLength][1:]
		// Match public key with signature
		for _, publicKey := range publicKeys {
			pubKey, err := crypto.DecodePoint(publicKey[1:])
			if err != nil {
				return err
			}
			err = crypto.Verify(*pubKey, data, sign)
			if err == nil {
				hash := sha256.Sum256(publicKey)
				if _, ok := verified[hash]; ok {
					return errors.New("duplicated signatures")
				}
				verified[hash] = struct{}{}
				break // back to public keys loop
			}
		}
	}
	// Check signatures count
	if len(verified) < m {
		return errors.New("matched signatures not enough")
	}

	return nil
}
