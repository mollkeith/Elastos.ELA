// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/dpos"
	"github.com/elastos/Elastos.ELA/dpos/account"
	dlog "github.com/elastos/Elastos.ELA/dpos/log"
	msg2 "github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet"
	"github.com/elastos/Elastos.ELA/elanet/routes"
	"github.com/elastos/Elastos.ELA/mempool"
	"github.com/elastos/Elastos.ELA/p2p"
	"github.com/elastos/Elastos.ELA/p2p/msg"
	"github.com/elastos/Elastos.ELA/pow"
	"github.com/elastos/Elastos.ELA/servers"
	"github.com/elastos/Elastos.ELA/servers/httpjsonrpc"
	"github.com/elastos/Elastos.ELA/servers/httpnodeinfo"
	"github.com/elastos/Elastos.ELA/servers/httprestful"
	"github.com/elastos/Elastos.ELA/servers/httpwebsocket"
	"github.com/elastos/Elastos.ELA/utils"
	"github.com/elastos/Elastos.ELA/utils/elalog"
	"github.com/elastos/Elastos.ELA/utils/signal"
)

const (
	// dataPath indicates the path storing the chain data.
	dataPath = "data"

	// nodeLogPath indicates the path storing the node log.
	nodeLogPath = "logs/node"

	// checkpointPath indicates the path storing the checkpoint data.
	checkpointPath = "checkpoints"

	// nodePrefix indicates the prefix of node version.
	nodePrefix = "ela-"
)

var (
	// Version generated when build program.
	Version string

	// GoVersion version at build.
	GoVersion string

	// The interval to print out peer-to-peer network state.
	printStateInterval = time.Minute
)

func main() {

	// Setting config
	setting := settings.NewSettings()
	config := setting.SetupConfig(true, "Copyright (c) 2017-"+
		fmt.Sprint(time.Now().Year())+" The Elastos Foundation", nodePrefix+Version+" "+GoVersion)

	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// This value was arrived at with the help of profiling live usage.
	if config.MemoryFirst {
		debug.SetGCPercent(10)
	}

	// Init logger
	setupLog(config)

	// Debug
	json.MarshalIndent(config, "", "\t")

	// Start Node
	startNode(config)
}

func startNode(cfg *config.Configuration) {
	log.Infof("Node version: %s, %s, %s", Version, GoVersion, cfg.ActiveNet)
	if cfg.ProfilePort != 0 {
		go utils.StartPProf(cfg.ProfilePort, cfg.ProfileHost)
	}

	flagDataDir := config.DataDir
	if cfg.DataDir != "" {
		flagDataDir = cfg.DataDir
	}
	dataDir := filepath.Join(flagDataDir, dataPath)

	ckpManager := checkpoint.NewManager(cfg)
	ckpManager.SetDataPath(filepath.Join(dataDir, checkpointPath))

	var acc account.Account
	if cfg.DPoSConfiguration.EnableArbiter {
		var err error
		var password []byte
		if cfg.Password != "" {
			password = []byte(cfg.Password)
		} else {
			password, err = utils.GetPassword()
		}
		if err != nil {
			printErrorAndExit(err)
		}
		acc, err = account.Open(password, cfg.WalletPath)
		if err != nil {
			printErrorAndExit(err)
		}
	}
	var interrupt = signal.NewInterrupt()

	// fixme remove singleton Ledger
	ledger := blockchain.Ledger{}

	// Initializes the foundation address
	blockchain.FoundationAddress = *cfg.FoundationProgramHash
	chainStore, err := blockchain.NewChainStore(dataDir, cfg)
	if err != nil {
		printErrorAndExit(err)
	}
	defer chainStore.Close()
	ledger.Store = chainStore // fixme

	txMemPool := mempool.NewTxPool(cfg, ckpManager)
	blockMemPool := mempool.NewBlockPool(cfg)
	blockMemPool.Store = chainStore

	blockchain.DefaultLedger = &ledger // fixme

	committee := crstate.NewCommittee(cfg, ckpManager)
	ledger.Committee = committee

	arbiters, err := state.NewArbitrators(cfg, committee, ledger.GetAmount,
		committee.TryUpdateCRMemberInactivity,
		committee.TryRevertCRMemberInactivity,
		committee.TryUpdateCRMemberIllegal,
		committee.TryRevertCRMemberIllegal,
		committee.UpdateCRInactivePenalty,
		committee.RevertUpdateCRInactivePenalty,
		ckpManager,
	)
	if err != nil {
		printErrorAndExit(err)
	}
	ledger.Arbitrators = arbiters // fixme

	chain, err := blockchain.New(chainStore, cfg,
		arbiters.State, committee, ckpManager)
	if err != nil {
		printErrorAndExit(err)
	}
	// BEFORE anything else, and on every boot regardless of configuration: refuse to
	// start a node whose store still records a forced rollback as started-and-
	// unfinished while this node is not configured to finish it. Every other check
	// below is gated on the trigger being set, which is precisely what an operator
	// removes after reading the completion line -- and if the process died inside the
	// ffldb flush window, that line described a rewind that had not reached disk.
	// Disarming there used to bring the node back up on the pre-rollback chain,
	// serving the discarded blocks, silently. The marker outlives that crash by
	// construction (it is flushed before the first destructive step), so this check
	// sees it.
	if e := chain.CheckAbandonedForcedRollback(); e != nil {
		printErrorAndExit(e)
	}
	// Forced rollback runs BEFORE chain.Init so that checkpoint restoration and
	// derived-state rebuild happen against the already-rewound chain rather than
	// against state from a height that no longer exists. blockchain.New has
	// populated chain.Nodes by this point, which is all the rewind needs.
	//
	// This replaces the manual `ela-cli rollback` step: operators update the
	// binary and restart, nothing else. The rollback is armed only when this node
	// actually holds the targeted block, so it is idempotent and a no-op for
	// fresh nodes.
	//
	// ARMED IS NOT APPLIED. The variable below says only "this node holds the chain
	// the rollback targets". It is deliberately no longer used as a stand-in for
	// "the rollback happened": that conflation is what made 48/48 rehearsal nodes
	// decline a capacity-exceeded rewind here and then refuse to start further down,
	// and -- in the silent variant, when the restored checkpoint happens to land
	// below the target -- what let a node come up UN-ROLLED-BACK on the exploit
	// chain. Whether the rollback was applied is established below by
	// VerifyForcedRollbackApplied, against the persisted store.
	forcedRollbackArmed, e := chain.ForcedRollbackArmed()
	if e != nil {
		printErrorAndExit(e)
	}
	if cfg.ForcedRollbackTrigger != "" && chain.GetHeight() > cfg.ForcedRollbackHeight {
		// Loud diagnostic: a mis-encoded (e.g. reversed/explorer byte order)
		// trigger silently disarms the rollback and leaves the node on the
		// corrupt chain. Print configured vs actual so operators can catch it.
		if actual, herr := chain.GetBlockHash(cfg.ForcedRollbackHeight + 1); herr == nil {
			log.Warnf("forced rollback trigger check: configured=%s actual(block %d)=%s armed=%v",
				cfg.ForcedRollbackTrigger, cfg.ForcedRollbackHeight+1, actual.ReversedString(), forcedRollbackArmed)
		}
	}
	forcedRollbackApplied := false
	if forcedRollbackArmed {
		log.Warnf("forced rollback armed: this node holds block %s; rewinding to %d",
			cfg.ForcedRollbackTrigger, cfg.ForcedRollbackHeight)
		// PRE-FLIGHT (B5). The armed path used to go straight into the rewind, so a
		// store already damaged by an earlier interrupted rollback was discovered
		// mid-rewind. MEASURED: it aborts on an internal transaction-index assertion
		// that names two raw hashes, carries no sentinel and offers no remedy --
		// "fails closed but opaquely", at the point in restart day where that costs
		// the most. The scan runs BEFORE anything destructive, classifies the damage
		// and names a remedy for it.
		if e := chain.PreflightForcedRollback(); e != nil {
			printErrorAndExit(e)
		}
		if e := chain.ForceRollback(interrupt.C); e != nil {
			// EVERY failure is fatal, including ErrForcedRollbackExceedsCapacity.
			// That sentinel used to be swallowed here so a late upgrader was not
			// bricked into a boot loop -- but "not bricked" meant booting on the
			// EXPLOIT chain, which is strictly worse: such a node joins the recovered
			// network on the removed chain and, holding an on-duty arbiter seat,
			// stalls it (rehearsal finding 3). A node that cannot complete the
			// rollback must not join the recovered network. The remedies are in the
			// error text and are operator-actionable; refusing to start is the loud,
			// unambiguous outcome.
			//
			// ErrForcedRollbackInterrupted is fatal for a different reason: it is NOT
			// a corruption report. The rewind stops at a block boundary and continues
			// on the next start, because a block's header-index row -- the row
			// b.Nodes is rebuilt from, and therefore the row both the arming predicate
			// and the rewind bound depend on -- is now deleted only after all of that
			// block's destructive work is durably committed.
			printErrorAndExit(e)
		}
		forcedRollbackApplied = true
	} else if cfg.ForcedRollbackTrigger != "" && cfg.ForcedRollbackHeight != 0 &&
		cfg.ForcedRollbackHeight != config.DisabledForcedRollbackHeight {
		// The boot a RATCHETED node comes up on. Under the shipped ordering each
		// interrupted rewind destroyed one block-header-index row before its rollback
		// transaction committed, so after (tip-target) restarts the arming predicate
		// went false at exactly the target while every discarded block -- including
		// block 2,260,451 -- was still main-chain indexed, still in the raw store and
		// still served by hash, with none of its UTXO/derived-state rollback applied.
		// Neither shipped safety net could see it: the height assertion was
		// tautological and the checkpoint assertion was guarded by the armed flag,
		// which is false on precisely this boot.
		if e := chain.CheckForcedRollbackResidue(); e != nil {
			printErrorAndExit(e)
		}
	}
	// THE post-condition, and it runs on EVERY boot of a configured node -- armed or
	// not, rewound in this process or in an earlier one. The check it replaces
	// compared chain.GetHeight() against the target; GetHeight() is len(b.Nodes)-1
	// and the rewind loop's exit condition is exactly len(b.Nodes)-1 <= target, so it
	// restated the loop and could not fail for any store contents whatsoever. This
	// one asserts BYTES ON DISK: the targeted block must be absent from the
	// main-chain index, the block-header index and the raw block store. It is three
	// point lookups on the common path, and it is the check that makes it impossible
	// for a configured node to reach the network above the target still holding the
	// block the recovery removes.
	if e := chain.VerifyForcedRollbackApplied(); e != nil {
		printErrorAndExit(e)
	}

	if err = chain.Init(interrupt.C); err != nil {
		printErrorAndExit(err)
	}
	if err = chain.MigrateOldDB(interrupt.C, pgBar.Start,
		pgBar.Increase, dataDir, cfg); err != nil {
		printErrorAndExit(err)
	}
	pgBar.Stop()

	ledger.Blockchain = chain // fixme
	blockMemPool.Chain = chain
	arbiters.RegisterFunction(chain.GetHeight, chain.GetBestBlockHash,
		chain.GetBlock, chain.UTXOCache.GetTxReference)

	routesCfg := &routes.Config{TimeSource: chain.TimeSource}
	if acc != nil {
		routesCfg.PID = acc.PublicKeyBytes()
		routesCfg.Addr = net.JoinHostPort(cfg.DPoSConfiguration.IPAddress,
			strconv.FormatUint(uint64(cfg.DPoSConfiguration.DPoSPort), 10))
		routesCfg.Sign = acc.Sign
	}

	route := routes.New(routesCfg)
	netServer, err := elanet.NewServer(dataDir, &elanet.Config{
		Chain:          chain,
		ChainParams:    cfg,
		PermanentPeers: cfg.PermanentPeers,
		TxMemPool:      txMemPool,
		BlockMemPool:   blockMemPool,
		Routes:         route,
	}, nodePrefix+Version)
	if err != nil {
		printErrorAndExit(err)
	}
	routesCfg.IsCurrent = netServer.IsCurrent
	routesCfg.RelayAddr = netServer.RelayInventory
	blockMemPool.IsCurrent = netServer.IsCurrent

	arbiters.State.RegisterFuncitons(&state.StateFuncsConfig{
		GetHeight: chainStore.GetHeight,
		IsCurrent: netServer.IsCurrent,
		Broadcast: func(msg p2p.Message) {
			netServer.BroadcastMessage(msg)
		},
		AppendToTxpool:                      txMemPool.AppendToTxPool,
		CreateDposV2RealWithdrawTransaction: chain.CreateDposV2RealWithdrawTransaction,
		CreateVotesRealWithdrawTransaction:  chain.CreateVotesRealWithdrawTransaction,
	})

	if acc != nil {
		dlog.Init(flagDataDir, uint8(cfg.PrintLevel), cfg.MaxPerLogSize, cfg.MaxLogsSize)
		arbitrator, err := dpos.NewArbitrator(acc, dpos.Config{
			EnableEventLog: true,
			Chain:          chain,
			ChainParams:    cfg,
			Arbitrators:    arbiters,
			Server:         netServer,
			TxMemPool:      txMemPool,
			BlockMemPool:   blockMemPool,
			Broadcast: func(msg p2p.Message) {
				netServer.BroadcastMessage(msg)
			},
			AnnounceAddr: route.AnnounceAddr,
			NodeVersion:  nodePrefix + Version,
			Addr:         routesCfg.Addr,
		})
		if err != nil {
			printErrorAndExit(err)
		}
		routesCfg.OnCipherAddr = arbitrator.OnCipherAddr
		servers.Arbiter = arbitrator
		arbitrator.Start()
		defer arbitrator.Stop()
	}

	committee.RegisterFuncitons(&crstate.CommitteeFuncsConfig{
		GetTxReference:                   chain.UTXOCache.GetTxReference,
		GetUTXO:                          chainStore.GetFFLDB().GetUTXO,
		GetHeight:                        chainStore.GetHeight,
		CreateCRAppropriationTransaction: chain.CreateCRCAppropriationTransaction,
		CreateCRAssetsRectifyTransaction: chain.CreateCRAssetsRectifyTransaction,
		CreateCRRealWithdrawTransaction:  chain.CreateCRRealWithdrawTransaction,
		IsCurrent:                        netServer.IsCurrent,
		Broadcast: func(msg p2p.Message) {
			netServer.BroadcastMessage(msg)
		},
		AppendToTxpool:     txMemPool.AppendToTxPool,
		GetCurrentArbiters: arbiters.GetCurrentArbitratorKeys,
	})

	servers.Compile = Version
	servers.ChainParams = cfg
	servers.Chain = chain
	servers.Store = chainStore
	servers.TxMemPool = txMemPool
	servers.Server = netServer
	servers.Arbiters = arbiters
	servers.Pow = pow.NewService(&pow.Config{
		PayToAddr:   cfg.PowConfiguration.PayToAddr,
		MinerInfo:   cfg.PowConfiguration.MinerInfo,
		Chain:       chain,
		ChainParams: cfg,
		TxMemPool:   txMemPool,
		BlkMemPool:  blockMemPool,
		BroadcastBlock: func(block *types.Block) {
			hash := block.Hash()
			netServer.RelayInventory(msg.NewInvVect(msg.InvTypeBlock, &hash), block)
		},
		Arbitrators: arbiters,
	})

	ckpManager.SetNeedSave(true)
	// initialize producer state after arbiters has initialized.
	if err = chain.InitCheckpoint(interrupt.C, pgBar.Start,
		pgBar.Increase); err != nil {
		printErrorAndExit(err)
	}
	pgBar.Stop()

	// Safety net for the forced rollback. InitCheckpoint restored the checkpoint
	// snapshots and replayed derived state forward to the rewound tip. init replay
	// skips SetHeight, so each checkpoint's GetHeight() still equals its RESTORED
	// file height here. The load-bearing property is that every restored snapshot is
	// STRICTLY BELOW the rewound target -- only then is the baseline provably
	// pre-exploit. MaxHeight() checks the highest restored height directly (SafeHeight
	// is a min-of-(GetHeight-720) and could not detect a single tampered snapshot
	// sitting at/above the target). If any restored snapshot is at/above the target,
	// derived state may carry exploit-era arbiters: refuse to start.
	//
	// NOTE: this asserts the replay BASELINE, not the rebuilt CONTENT. A byte-level
	// comparison of the derived arbiter/CR set at the target against a freshly-synced
	// reference is the definitive check and is gated on the testnet reproduction.
	//
	// The condition is deliberately NOT the ARMED flag. Armed means only that this
	// node held the targeted chain when it booted; on the capacity-declined path it
	// was true while the node sat, un-rewound, thousands of blocks ABOVE the target,
	// where this assertion is not merely useless but actively misleading -- it fires
	// on the exploit-era checkpoint of a node whose real defect is that it never
	// rolled back. The first disjunct is now the APPLIED fact (the rewind ran in this
	// process and the persisted store was verified), and the second covers the boot
	// on which an already-rewound node comes up -- the rewind having happened in an
	// earlier process -- so a snapshot that drifted to/above the target between runs
	// is still caught.
	if forcedRollbackApplied || (cfg.ForcedRollbackTrigger != "" &&
		cfg.ForcedRollbackHeight != 0 &&
		cfg.ForcedRollbackHeight != config.DisabledForcedRollbackHeight &&
		chain.GetHeight() <= cfg.ForcedRollbackHeight) {
		mh := chain.CkpManager.MaxHeight()
		if mh >= cfg.ForcedRollbackHeight {
			printErrorAndExit(fmt.Errorf(
				"forced rollback: a restored checkpoint height %d is >= rewound target %d; the "+
					"snapshot is not strictly pre-target, derived state may be exploit-era -- "+
					"refusing to start", mh, cfg.ForcedRollbackHeight))
		}
		log.Warnf("forced rollback: post-rebuild baseline OK (max restored checkpoint %d < target %d, tip %d)",
			mh, cfg.ForcedRollbackHeight, chain.GetHeight())
	}

	// todo remove me
	if chain.GetHeight() > cfg.DPoSV2StartHeight {
		msg2.SetPayloadVersion(msg2.DPoSV2Version)
	}

	// Add small cross chain transactions to transaction pool
	txs, _ := chain.GetDB().GetSmallCrossTransferTxs()
	for _, tx := range txs {
		if err := txMemPool.AppendToTxPoolWithoutEvent(tx); err != nil {
			continue
		}
	}

	log.Info("Start the P2P networks")
	netServer.Start()
	defer netServer.Stop()

	log.Info("Start services")
	if cfg.EnableRPC {
		go httpjsonrpc.StartRPCServer()
	}
	if cfg.HttpRestStart {
		go httprestful.StartServer()
	}
	if cfg.HttpWsStart {
		go httpwebsocket.Start()
	}
	if cfg.HttpInfoStart {
		go httpnodeinfo.StartServer()
	}

	go printSyncState(chain, netServer)

	waitForSyncFinish(netServer, interrupt.C)
	if interrupt.Interrupted() {
		return
	}
	log.Info("Start consensus")
	if cfg.PowConfiguration.AutoMining {
		log.Info("Start POW Services")
		go servers.Pow.Start()
	}
	servers.Pow.ListenForRevert()

	<-interrupt.C
}

func printErrorAndExit(err error) {
	log.Error(err)
	os.Exit(-1)
}

func waitForSyncFinish(server elanet.Server, interrupt <-chan struct{}) {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

out:
	for {
		select {
		case <-ticker.C:
			if server.IsCurrent() {
				break out
			}

		case <-interrupt:
			break out
		}
	}
}

func printSyncState(bc *blockchain.BlockChain, server elanet.Server) {
	statlog := elalog.NewBackend(logger.Writer()).Logger("STAT",
		elalog.LevelInfo)

	ticker := time.NewTicker(printStateInterval)
	defer ticker.Stop()

	for range ticker.C {
		var buf bytes.Buffer
		buf.WriteString("-> ")
		buf.WriteString(strconv.FormatUint(uint64(bc.GetHeight()), 10))
		peers := server.ConnectedPeers()
		buf.WriteString(" [")
		for i, p := range peers {
			buf.WriteString(strconv.FormatUint(uint64(p.ToPeer().Height()), 10))
			buf.WriteString(" ")
			buf.WriteString(p.ToPeer().String())
			if i != len(peers)-1 {
				buf.WriteString(", ")
			}
		}
		buf.WriteString("]")
		statlog.Info(buf.String())
	}
}
