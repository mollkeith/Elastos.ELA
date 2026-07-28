// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/mempool"
)

const (
	maxNonce               = ^uint32(0) // 2^32 - 1
	updateInterval         = 30 * time.Second
	createAuxBlockInterval = 5 * time.Second

	// maxDiscreteMiningAttempts bounds the block generation retries of a single
	// DiscreteMining call. F-163: that retry used to be an unbounded `continue`.
	maxDiscreteMiningAttempts = 100
)

type Config struct {
	PayToAddr      string
	MinerInfo      string
	Chain          *blockchain.BlockChain
	ChainParams    *config.Configuration
	TxMemPool      *mempool.TxPool
	BlkMemPool     *mempool.BlockPool
	BroadcastBlock func(block *types.Block)
	Arbitrators    state.Arbitrators
}

// maxAuxBlockPoolSize bounds the aux-block pool.
//
// WHY A BOUND IS REQUIRED. The pool is emptied ONLY when the chain height changes
// (CreateAuxBlock: `if pow.preChainHeight != pow.chain.GetHeight()`). On a STALLED
// chain the height by definition does not change, while createAuxBlockInterval is
// 5 seconds -- so a merge-mining pool polling createauxblock adds a new entry, with
// a new hash, every 5 seconds, and nothing ever removes it. That is 720 entries an
// hour, unbounded.
//
// A stalled chain is not a hypothetical: it is EXACTLY the restart condition. The
// recovery requires at least four hours of stall before the in-block RevertToPOW
// rule can fire, and the PoW window may run far longer. The node this exhausts is
// the pool's node -- the one node that must stay healthy for the chain to restart
// at all.
//
// 720 entries is one hour of regeneration at the 5-second interval, which is far
// more history than SubmitAuxBlock needs: a submitted block is looked up by hash
// only until the height moves, and the height moving clears the pool outright.
const maxAuxBlockPoolSize = 720

type AuxBlockPool struct {
	mutex       sync.RWMutex
	mapNewBlock map[common.Uint256]*types.Block
	// order records insertion order so the oldest entry can be evicted when the
	// bound is reached. Go map iteration is randomised, so evicting "some" entry
	// without this would drop the block a pool is currently mining as readily as
	// a stale one.
	order []common.Uint256
}

func (p *AuxBlockPool) AppendBlock(block *types.Block) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	hash := block.Hash()
	if _, exists := p.mapNewBlock[hash]; exists {
		return
	}

	// Evict oldest-first until there is room. A loop rather than a single evict so
	// the bound still holds if maxAuxBlockPoolSize is ever lowered on a live pool.
	for len(p.order) >= maxAuxBlockPoolSize && len(p.order) > 0 {
		oldest := p.order[0]
		p.order = p.order[1:]
		delete(p.mapNewBlock, oldest)
	}

	p.mapNewBlock[hash] = block
	p.order = append(p.order, hash)
}

func (p *AuxBlockPool) ClearBlock() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for key := range p.mapNewBlock {
		delete(p.mapNewBlock, key)
	}
	// Release the backing array too: on a long stall this slice is the larger of
	// the two allocations, and keeping its capacity would defeat the eviction.
	p.order = nil
}

func (p *AuxBlockPool) GetBlock(hash common.Uint256) (*types.Block, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	block, ok := p.mapNewBlock[hash]
	return block, ok
}

type Service struct {
	PayToAddr   string
	MinerInfo   string
	chain       *blockchain.BlockChain
	chainParams *config.Configuration
	txMemPool   *mempool.TxPool
	blkMemPool  *mempool.BlockPool
	broadcast   func(block *types.Block)
	arbiters    state.Arbitrators

	mutex           sync.Mutex
	started         bool
	discreteMining  bool
	auxBlockPool    AuxBlockPool
	preChainHeight  uint32
	preTime         time.Time
	currentAuxBlock *types.Block

	wg   sync.WaitGroup
	quit chan struct{}

	lock      sync.Mutex
	lastBlock *types.Block
}

func (pow *Service) GetDefaultTxVersion(height uint32) common2.TransactionVersion {
	var v common2.TransactionVersion = 0
	// when block height greater than H2 use the version TxVersion09
	if height >= pow.chainParams.PublicDPOSHeight {
		v = common2.TxVersion09
	}
	return v
}

func (pow *Service) CreateCoinbaseTx(minerAddr string, height uint32) (interfaces.Transaction, error) {

	crRewardAddr := pow.chainParams.FoundationProgramHash
	if height >= pow.chainParams.CRConfiguration.CRCommitteeStartHeight {
		crRewardAddr = pow.chainParams.CRConfiguration.CRAssetsProgramHash
	}

	minerProgramHash, err := common.Uint168FromAddress(minerAddr)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, rand.Uint64())
	txAttr := common2.NewAttribute(common2.Nonce, nonce)
	tx := functions.CreateTransaction(
		pow.GetDefaultTxVersion(height),
		common2.CoinBase,
		payload.CoinBaseVersion,
		&payload.CoinBase{
			Content: []byte(pow.MinerInfo),
		},
		[]*common2.Attribute{&txAttr},
		[]*common2.Input{
			{
				Previous: common2.OutPoint{
					TxID:  common.EmptyHash,
					Index: math.MaxUint16,
				},
				Sequence: math.MaxUint32,
			},
		},
		[]*common2.Output{
			{
				AssetID:     core.ELAAssetID,
				Value:       0,
				ProgramHash: *crRewardAddr,
				Type:        common2.OTNone,
				Payload:     &outputpayload.DefaultOutput{},
			},
			{
				AssetID:     core.ELAAssetID,
				Value:       0,
				ProgramHash: *minerProgramHash,
				Type:        common2.OTNone,
				Payload:     &outputpayload.DefaultOutput{},
			},
		},
		height,
		[]*pg.Program{},
	)

	return tx, nil
}

func (pow *Service) CreateRecordSponsorTx(sponsor []byte, height uint32) (interfaces.Transaction, error) {

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, rand.Uint64())
	txAttr := common2.NewAttribute(common2.Nonce, nonce)
	tx := functions.CreateTransaction(
		pow.GetDefaultTxVersion(height),
		common2.RecordSponsor,
		payload.RecordSponsorVersion,
		&payload.RecordSponsor{
			Sponsor: sponsor,
		},
		[]*common2.Attribute{&txAttr},
		[]*common2.Input{},
		[]*common2.Output{},
		height,
		[]*pg.Program{},
	)

	return tx, nil
}

func (pow *Service) AssignCoinbaseTxRewards(block *types.Block, totalReward common.Fixed64) error {
	activeHeight := pow.arbiters.GetDPoSV2ActiveHeight()

	if activeHeight != math.MaxUint32 && block.Height > activeHeight+1 {
		rewardCyberRepublic := common.Fixed64(math.Ceil(float64(totalReward) * 0.3))
		rewardDposArbiter := common.Fixed64(math.Ceil(float64(totalReward) * 0.35))
		rewardMergeMiner := common.Fixed64(totalReward) - rewardCyberRepublic - rewardDposArbiter
		block.Transactions[0].Outputs()[0].Value = rewardCyberRepublic
		block.Transactions[0].Outputs()[1].Value = rewardMergeMiner

		var dposRewardProgramHash common.Uint168
		if pow.arbiters.IsInPOWMode() {
			dposRewardProgramHash = *pow.chainParams.DestroyELAProgramHash
			block.Transactions[0].Outputs()[0].ProgramHash = *pow.chainParams.DestroyELAProgramHash
		} else {
			dposRewardProgramHash = *pow.chainParams.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash
		}

		if rewardDposArbiter > common.Fixed64(0) {
			output := append(block.Transactions[0].Outputs(), &common2.Output{
				AssetID:     core.ELAAssetID,
				Value:       rewardDposArbiter,
				ProgramHash: dposRewardProgramHash,
				Payload:     &outputpayload.DefaultOutput{},
			})
			block.Transactions[0].SetOutputs(output)
		}
		return nil
	}

	// main version >= H2
	if block.Height >= pow.chainParams.PublicDPOSHeight {
		rewardCyberRepublic := common.Fixed64(math.Ceil(float64(totalReward) * 0.3))
		rewardDposArbiter := common.Fixed64(math.Ceil(float64(totalReward) * 0.35))
		rewardMergeMiner := common.Fixed64(totalReward) - rewardCyberRepublic - rewardDposArbiter

		if rewards := pow.arbiters.GetArbitersRoundReward(); len(rewards) > 0 {

			var dposChange common.Fixed64
			var err error
			if dposChange, err = pow.distributeDPOSReward(block.Transactions[0],
				rewards); err != nil {
				return err
			}
			rewardMergeMiner += dposChange
		}

		block.Transactions[0].Outputs()[0].Value = rewardCyberRepublic
		block.Transactions[0].Outputs()[1].Value = rewardMergeMiner
		if pow.arbiters.IsInPOWMode() {
			block.Transactions[0].Outputs()[0].ProgramHash = *pow.chainParams.DestroyELAProgramHash
		}
		return nil
	}

	// version [0, H2)
	// PoW miners and DPoS are each equally allocated 35%. The remaining 30% goes to the Cyber Republic fund
	rewardCyberRepublic := common.Fixed64(float64(totalReward) * 0.3)
	rewardMergeMiner := common.Fixed64(float64(totalReward) * 0.35)
	rewardDposArbiter := common.Fixed64(totalReward) - rewardCyberRepublic - rewardMergeMiner
	block.Transactions[0].Outputs()[0].Value = rewardCyberRepublic
	block.Transactions[0].Outputs()[1].Value = rewardMergeMiner
	block.Transactions[0].SetOutputs(append(block.Transactions[0].Outputs(), &common2.Output{
		AssetID:     core.ELAAssetID,
		Value:       rewardDposArbiter,
		ProgramHash: blockchain.FoundationAddress,
	}))
	return nil
}

func (pow *Service) distributeDPOSReward(coinBaseTx interfaces.Transaction,
	rewards map[common.Uint168]common.Fixed64) (common.Fixed64, error) {
	for ownerHash, reward := range rewards {
		coinBaseTx.SetOutputs(append(coinBaseTx.Outputs(), &common2.Output{
			AssetID:     core.ELAAssetID,
			Value:       reward,
			ProgramHash: ownerHash,
			Type:        common2.OTNone,
			Payload:     &outputpayload.DefaultOutput{},
		}))
	}
	return pow.arbiters.GetFinalRoundChange(), nil
}

func (pow *Service) GenerateBlock(minerAddr string,
	txPerBlock uint32) (*types.Block, error) {
	bestChain := pow.chain.BestChain
	nextBlockHeight := bestChain.Height + 1
	coinBaseTx, err := pow.CreateCoinbaseTx(minerAddr, nextBlockHeight)
	if err != nil {
		return nil, err
	}
	header := common2.Header{
		Version:    0,
		Previous:   *pow.chain.BestChain.Hash,
		MerkleRoot: common.EmptyHash,
		Timestamp:  uint32(pow.chain.MedianAdjustedTime().Unix()),
		Bits:       pow.chainParams.PowConfiguration.PowLimitBits,
		Height:     nextBlockHeight,
		Nonce:      0,
	}

	msgBlock := &types.Block{
		Header:       header,
		Transactions: []interfaces.Transaction{},
	}

	msgBlock.Transactions = append(msgBlock.Transactions, coinBaseTx)
	txCount := uint32(1)
	totalTxsSize := coinBaseTx.GetSize()
	totalTxFee := common.Fixed64(0)

	if bestChain.Height+1 >= pow.chainParams.DPoSConfiguration.RecordSponsorStartHeight {
		bestBlock, err := pow.chain.GetDposBlockByHash(*bestChain.Hash)
		if err != nil {
			return nil, err
		}
		// NX-01/NX-05 producer side. This raw read is now the ONLY derivation of the
		// recorded sponsor anywhere in the system: the validator no longer derives one at
		// all (blockchain/blockvalidator.go CheckBlockContext), so the producer/validator
		// asymmetry that made an operator sponsors-file entry a deterministic block
		// rejection at/above the gate cannot arise. Do NOT reintroduce an override lookup
		// here or a binding there without making both sides read the same committed data.
		// The Confirm nil-check is crash-hardening (ungated): HaveConfirm and Confirm are
		// independent wire fields on types.DposBlock, so a stored or peer-supplied record
		// can set the flag with no payload and nil-deref the miner here. A node whose own
		// store is that corrupt then omits the RecordSponsor tx and its block is refused
		// by the presence check in CheckBlockContext -- which is a rejected block instead
		// of a dead miner, and a panic is not an acceptance decision, so this rides no gate.
		if bestBlock.HaveConfirm && bestBlock.Confirm != nil {
			recordSponsorTx, err := pow.CreateRecordSponsorTx(bestBlock.Confirm.Proposal.Sponsor, nextBlockHeight)
			if err != nil {
				return nil, err
			}
			msgBlock.Transactions = append(msgBlock.Transactions, recordSponsorTx)
			txCount++
			totalTxsSize += recordSponsorTx.GetSize()
		}
	}

	txs := pow.txMemPool.GetTxsInPool()
	isHighPriority := func(tx interfaces.Transaction) bool {
		if tx.IsRevertToPOW() || tx.IsRevertToDPOS() ||
			tx.IsIllegalTypeTx() || tx.IsInactiveArbitrators() ||
			tx.IsSideChainPowTx() || tx.IsUpdateVersion() ||
			tx.IsActivateProducerTx() || tx.IsCRCAppropriationTx() ||
			tx.IsCRAssetsRectifyTx() || tx.IsNextTurnDPOSInfoTx() {
			return true
		}

		return false
	}

	sort.Slice(txs, func(i, j int) bool {
		if isHighPriority(txs[i]) {
			return true
		}
		if isHighPriority(txs[j]) {
			return false
		}
		return txs[i].FeePerKB() > txs[j].FeePerKB()
	})

	var proposalsUsedAmount common.Fixed64
	for _, tx := range txs {
		if tx.IsRecordSponorTx() {
			continue
		}

		size := totalTxsSize + tx.GetSize()
		if size > int(pact.MaxBlockContextSize) {
			continue
		}
		totalTxsSize = size
		if txCount >= txPerBlock {
			log.Warn("txCount reached max MaxTxPerBlock")
			break
		}

		if !blockchain.IsFinalizedTransaction(tx, nextBlockHeight) {
			continue
		}
		_, errCode := pow.chain.CheckTransactionContext(nextBlockHeight, tx, proposalsUsedAmount, header.Timestamp)
		if errCode != nil {
			log.Warn("check transaction context failed, wrong transaction:", tx.Hash().String())
			continue
		}
		msgBlock.Transactions = append(msgBlock.Transactions, tx)
		totalTxFee += tx.Fee()
		if tx.IsCRCProposalTx() {
			blockchain.RecordCRCProposalAmount(&proposalsUsedAmount, tx)
		}
		txCount++
	}
	totalReward := totalTxFee + pow.chainParams.GetBlockReward(nextBlockHeight)
	pow.AssignCoinbaseTxRewards(msgBlock, totalReward)
	txHash := make([]common.Uint256, 0, len(msgBlock.Transactions))
	for _, tx := range msgBlock.Transactions {
		txHash = append(txHash, tx.Hash())
	}
	txRoot, err := crypto.ComputeRoot(txHash)
	if err != nil {
		log.Error(err.Error())
	}
	msgBlock.Header.MerkleRoot = txRoot
	msgBlock.Header.Bits, err = pow.chain.CalcNextRequiredDifficulty(bestChain, time.Now())
	return msgBlock, err
}

func (pow *Service) CreateAuxBlock(payToAddr string) (*types.Block, error) {
	pow.mutex.Lock()
	defer pow.mutex.Unlock()

	if pow.chain.GetHeight() == 0 || pow.preChainHeight != pow.chain.GetHeight() ||
		time.Now().After(pow.preTime.Add(createAuxBlockInterval)) {

		if pow.preChainHeight != pow.chain.GetHeight() {
			// Clear old blocks since they're obsolete now.
			pow.currentAuxBlock = nil
			pow.auxBlockPool.ClearBlock()
		}

		// Create new block with nonce = 0
		auxBlock, err := pow.GenerateBlock(payToAddr, pact.MaxTxPerBlock)
		if err != nil {
			return nil, err
		}

		// Update state only when CreateNewBlock succeeded
		pow.preChainHeight = pow.chain.GetHeight()
		pow.preTime = time.Now()

		// Save
		pow.currentAuxBlock = auxBlock
		pow.auxBlockPool.AppendBlock(auxBlock)
	}

	// At this point, currentAuxBlock is always initialised: If we make it here without creating
	// a new block above, it means that, in particular, preChainHeight == ServerNode.Height().
	// But for that to happen, we must already have created a currentAuxBlock in a previous call,
	// as preChainHeight is initialised only when currentAuxBlock is.
	if pow.currentAuxBlock == nil {
		return nil, fmt.Errorf("no block cached")
	}

	return pow.currentAuxBlock, nil
}

func (pow *Service) SubmitAuxBlock(hash *common.Uint256, auxPow *auxpow.AuxPow) error {
	pow.mutex.Lock()
	defer pow.mutex.Unlock()

	msgAuxBlock, ok := pow.auxBlockPool.GetBlock(*hash)
	if !ok {
		log.Debug("[json-rpc:SubmitAuxBlock] block hash unknown", hash)
		return fmt.Errorf("block hash unknown")
	}

	// F-041 submission side: derive ParentHash rather than trusting the submitter.
	//
	// At and above gate 1 CheckBlockSanity rejects a non-canonical AuxPow, but nothing has
	// ever enforced canonicality on this path: AuxPow.Check() and CheckProofOfWork() never
	// read ParentHash, so any 32 bytes verify and only pool convention made it canonical.
	// A pool whose stratum software sends the display-order hash, or leaves the field zero,
	// has every submission rejected from the first block of the restart. Since the restart
	// necessarily begins in PoW (the rewound tip is stale, so arbiters drop the first block
	// before it reaches consensus), that pool is the only thing that can move the chain.
	//
	// Deriving it here removes the dependency on third-party software entirely instead of
	// betting on it. It cannot invalidate a valid proof of work, because neither verifier
	// reads the field.
	//
	// ParMerkleIndex is deliberately NOT normalised: AuxPow.Check() DOES consume it, via
	// GetMerkleRoot(ParCoinbaseTx.Hash(), ParCoinBaseMerkle, ParMerkleIndex), so forcing it
	// to 0 could silently break a genuine merkle proof. A malleated index keeps its existing
	// gate rejection.
	//
	// UNGATED, and it needs no gate: this is block PRODUCTION. Retained blocks arrive from
	// peers over P2P and never pass through SubmitAuxBlock, so no retained block's verdict
	// can change. Same doctrine as the B2 SolveBlock stamp.
	//
	// Normalised on a COPY so the caller's structure is left exactly as the pool sent it.
	canonicalAuxPow := *auxPow
	canonicalAuxPow.ParentHash = canonicalAuxPow.ParBlockHeader.Hash()

	msgAuxBlock.Header.AuxPow = canonicalAuxPow
	_, _, err := pow.blkMemPool.AddDposBlock(&types.DposBlock{
		Block: msgAuxBlock,
	})
	return err
}

func (pow *Service) DiscreteMining(n uint32) ([]*common.Uint256, error) {
	// F-163: n comes straight off the RPC. Zero asks for no blocks at all, yet
	// the loop below still mines one - the i == n test can only be reached after
	// i has been incremented past zero - so "mine nothing" mined a block.
	// Reject it before any state is touched.
	if n == 0 {
		return nil, errors.New("count must be greater than 0")
	}

	pow.mutex.Lock()

	if pow.started || pow.discreteMining {
		pow.mutex.Unlock()
		return nil, errors.New("node is mining")
	}

	pow.started = true
	pow.discreteMining = true
	pow.mutex.Unlock()

	// F-163: every ordinary exit below cleared these two flags, but the
	// GenerateBlock failure path did not - it looped back with `continue`, so a
	// persistent generation failure spun forever holding pow.started, which
	// wedges mining for the life of the process and burns a core. Release on
	// every path, and bound the retries.
	defer func() {
		pow.mutex.Lock()
		pow.started = false
		pow.discreteMining = false
		pow.mutex.Unlock()
	}()

	log.Debugf("Pow generating %d blocks", n)
	i := uint32(0)
	blockHashes := make([]*common.Uint256, 0)

	log.Info("<================Discrete Mining==============>\n")
	for attempt := 0; attempt < maxDiscreteMiningAttempts; attempt++ {
		msgBlock, err := pow.GenerateBlock(pow.PayToAddr, pact.MaxTxPerBlock)
		if err != nil {
			log.Warn("Generate block failed, ", err.Error())
			continue
		}
		log.Info("Generate block, " + msgBlock.Hash().String())

		if pow.SolveBlock(msgBlock, nil) {
			if msgBlock.Header.Height == pow.chain.GetHeight()+1 {

				_, _, err := pow.blkMemPool.AddDposBlock(&types.DposBlock{
					Block: msgBlock,
				})
				if err != nil {
					return blockHashes, nil
				}

				h := msgBlock.Hash()
				blockHashes = append(blockHashes, &h)
				i++
				if i == n {
					return blockHashes, nil
				}
			}
		}

		return blockHashes, nil
	}

	return nil, errors.New("failed to generate block")
}

func (pow *Service) SolveBlock(msgBlock *types.Block, lastBlockHash *common.Uint256) bool {
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()
	// fake a btc blockheader and coinbase
	auxPow := auxpow.GenerateAuxPow(msgBlock.Hash())
	header := msgBlock.Header
	targetDifficulty := blockchain.CompactToBig(header.Bits)
	for i := uint32(0); i <= maxNonce; i++ {
		select {
		case <-ticker.C:
			log.Info("five second countdown ends. Re-generate block.")
			return false
		default:
			// Non-blocking select to fall through
		}

		auxPow.ParBlockHeader.Nonce = i
		hash := auxPow.ParBlockHeader.Hash() // solve parBlockHeader hash
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			// B2 (F-041 production side): stamp ParentHash for the WINNING
			// nonce, i.e. only once the parent header is final.
			// auxpow.GenerateAuxPow above never sets ParentHash, so every
			// self-mined block used to carry ParentHash == 0x00..00 - exactly
			// the encoding the canonical-AuxPow gate rejects at and above
			// StrictMoneyRangeHeight, which is the height the chain restarts
			// on. Stamping before the search would not help: the parent
			// header hash moves with the nonce, so the value would go stale on
			// the first iteration and still fail IsCanonical(). `hash` here IS
			// ParBlockHeader.Hash() at this exact nonce, so the stamp cannot
			// be stale for any nonce.
			//
			// Block PRODUCTION only, therefore ungated: ParentHash is not a
			// BtcHeader field, so ParBlockHeader.Hash() - and with it the
			// proof of work and AuxPow.Check() - is unchanged, and no
			// acceptance rule is touched. Retained history is never
			// re-produced here, so below-gate replay stays byte-identical.
			// ParMerkleIndex, the other field IsCanonical() pins, is already 0
			// out of GenerateAuxPow and is never mutated in this loop.
			auxPow.ParentHash = hash
			msgBlock.Header.AuxPow = *auxPow
			return true
		}
	}

	return false
}

func (pow *Service) Start() {
	pow.mutex.Lock()
	defer pow.mutex.Unlock()
	if pow.started || pow.discreteMining {
		log.Debug("cpuMining is already started")
	}

	pow.quit = make(chan struct{})
	pow.wg.Add(1)
	pow.started = true

	go pow.cpuMining()
}

func (pow *Service) Halt() {
	log.Info("POW Stop")
	pow.mutex.Lock()
	defer pow.mutex.Unlock()

	if !pow.started || pow.discreteMining {
		return
	}

	close(pow.quit)
	pow.wg.Wait()
	pow.started = false
}

func (pow *Service) cpuMining() {
out:
	for {
		select {
		case <-pow.quit:
			break out
		default:
			// Non-blocking select to fall through
		}
		log.Debug("<================Packing Block==============>")
		//time.Sleep(15 * time.Second)

		msgBlock, err := pow.GenerateBlock(pow.PayToAddr, pact.MaxTxPerBlock)
		if err != nil {
			log.Debug("generage block err", err)
			continue
		}

		//begin to mine the block with POW
		if pow.SolveBlock(msgBlock, nil) {
			log.Info("<================Solved Block==============>")
			//send the valid block to p2p networkd
			if msgBlock.Header.Height == pow.chain.GetHeight()+1 {

				inMainChain, isOrphan, err := pow.blkMemPool.AddDposBlock(&types.DposBlock{
					Block: msgBlock,
				})
				if err != nil {
					log.Debug(err)
					continue
				}

				if isOrphan || !inMainChain {
					continue
				}
			}
		}

	}

	pow.wg.Done()
}

func NewService(cfg *Config) *Service {
	block, _ := cfg.Chain.GetBlockByHash(*cfg.Chain.BestChain.Hash)
	pow := &Service{
		PayToAddr:      cfg.PayToAddr,
		MinerInfo:      cfg.MinerInfo,
		chain:          cfg.Chain,
		chainParams:    cfg.ChainParams,
		txMemPool:      cfg.TxMemPool,
		blkMemPool:     cfg.BlkMemPool,
		broadcast:      cfg.BroadcastBlock,
		arbiters:       cfg.Arbitrators,
		started:        false,
		discreteMining: false,
		auxBlockPool:   AuxBlockPool{mapNewBlock: make(map[common.Uint256]*types.Block)},
		lastBlock:      block,
	}

	return pow
}
