// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package server

import (
	"container/list"
	"sync"
)

// mruAddrSet provides a concurrency safe set of address keys that is limited
// to a maximum number of items with eviction of the least recently used entry
// when the limit is exceeded.  It follows the same pattern as mruNonceMap and
// exists so a per peer known address set cannot grow without bound (F-155).
type mruAddrSet struct {
	mtx      sync.Mutex
	addrMap  map[string]*list.Element // nearly O(1) lookups
	addrList *list.List               // O(1) insert, update, delete
	limit    uint
}

// Exists returns whether or not the passed address key is in the set.
//
// This function is safe for concurrent access.
func (m *mruAddrSet) Exists(key string) bool {
	m.mtx.Lock()
	_, exists := m.addrMap[key]
	m.mtx.Unlock()

	return exists
}

// Add adds the passed address key to the set and handles eviction of the
// oldest item if adding the new item would exceed the max limit.  Adding an
// existing item makes it the most recently used item.
//
// This function is safe for concurrent access.
func (m *mruAddrSet) Add(key string) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// When the limit is zero, nothing can be added to the set, so just
	// return.
	if m.limit == 0 {
		return
	}

	// When the entry already exists move it to the front of the list
	// thereby marking it most recently used.
	if node, exists := m.addrMap[key]; exists {
		m.addrList.MoveToFront(node)
		return
	}

	// Evict the least recently used entry (back of the list) if the new
	// entry would exceed the size limit for the set.  Also reuse the list
	// node so a new one doesn't have to be allocated.
	if uint(len(m.addrMap))+1 > m.limit {
		node := m.addrList.Back()
		lru := node.Value.(string)

		// Evict least recently used item.
		delete(m.addrMap, lru)

		// Reuse the list node of the item that was just evicted for the
		// new item.
		node.Value = key
		m.addrList.MoveToFront(node)
		m.addrMap[key] = node
		return
	}

	// The limit hasn't been reached yet, so just add the new item.
	node := m.addrList.PushFront(key)
	m.addrMap[key] = node
}

// Len returns the number of entries currently held by the set.
//
// This function is safe for concurrent access.
func (m *mruAddrSet) Len() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return len(m.addrMap)
}

// newMruAddrSet returns a new address key set that is limited to the number of
// entries specified by limit.  When the number of entries exceeds the limit,
// the oldest (least recently used) entry is removed to make room for the new
// entry.
func newMruAddrSet(limit uint) *mruAddrSet {
	return &mruAddrSet{
		addrMap:  make(map[string]*list.Element),
		addrList: list.New(),
		limit:    limit,
	}
}
