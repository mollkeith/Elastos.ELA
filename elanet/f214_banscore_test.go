// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package elanet

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/elanet/bloom"
	"github.com/elastos/Elastos.ELA/elanet/filter"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	elapeer "github.com/elastos/Elastos.ELA/elanet/peer"
	"github.com/elastos/Elastos.ELA/p2p/msg"
	p2ppeer "github.com/elastos/Elastos.ELA/p2p/peer"
)

// banScoreRecorder is a server.IPeer that only records the ban score charged
// to it.
type banScoreRecorder struct {
	persistent uint32
	transient  uint32
	reasons    []string
}

func (b *banScoreRecorder) ToPeer() *p2ppeer.Peer { return nil }

func (b *banScoreRecorder) AddBanScore(persistent, transient uint32, reason string) {
	b.persistent += persistent
	b.transient += transient
	b.reasons = append(b.reasons, reason)
}

func (b *banScoreRecorder) BanScore() uint32 { return b.persistent + b.transient }

// TestOnGetBlocksMetersOversizedLocator proves an oversized block locator is
// charged a ban score (F-214).  locateStartBlock walks every locator hash, so
// a peer that sends the protocol maximum of 500 hashes in a loop buys an
// unmetered chain index walk on the pristine tree.
//
// The handler is driven with no chain behind it, so it panics once it gets
// past the metering, which is exactly what this test needs to observe: the
// score has to be charged before the work is done.
func TestOnGetBlocksMetersOversizedLocator(t *testing.T) {
	recorder := &banScoreRecorder{}
	sp := &ServerPeer{
		Peer:   &elapeer.Peer{IPeer: recorder},
		server: &NetServer{},
	}

	locator := make([]*common.Uint256, msg.MaxBlockLocatorsPerMsg)
	for i := range locator {
		locator[i] = &common.Uint256{}
	}

	func() {
		defer func() { recover() }()
		sp.OnGetBlocks(nil, &msg.GetBlocks{Locator: locator})
	}()

	if recorder.transient == 0 {
		t.Fatalf("a getblocks carrying the protocol maximum of %d locator "+
			"hashes was not charged any ban score, the chain index walk it "+
			"triggers is unmetered (F-214)", msg.MaxBlockLocatorsPerMsg)
	}
}

// TestOnFilterLoadIsMetered proves a filterload message is charged a ban score
// (F-214).  On the pristine tree the handler has no metering at all, so a
// filterload loop spins filter loading for free.
func TestOnFilterLoadIsMetered(t *testing.T) {
	recorder := &banScoreRecorder{}
	sp := &ServerPeer{
		Peer:   &elapeer.Peer{IPeer: recorder},
		server: &NetServer{services: pact.SFTxFiltering},
		filter: filter.New(func(typ uint8) filter.TxFilter {
			return bloom.NewTxFilter()
		}),
	}

	filterLoad := &msg.FilterLoad{
		Filter:    make([]byte, 32),
		HashFuncs: 1,
		Tweak:     0,
		Flags:     0,
	}

	func() {
		defer func() { recover() }()
		sp.OnFilterLoad(nil, filterLoad)
	}()

	if recorder.transient == 0 {
		t.Fatal("a filterload message was not charged any ban score, the " +
			"handler is unmetered (F-214)")
	}
	if recorder.persistent != 0 {
		t.Fatalf("unexpected persistent ban score %d charged by %v",
			recorder.persistent, recorder.reasons)
	}
}
