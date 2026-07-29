// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package httpwebsocket

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type session struct {
	mtx  sync.Mutex
	id   int64
	conn *websocket.Conn

	// F-161: lastActive is written by this connection's read loop and read by
	// the session sweeper goroutine; time.Time is three words wide, so the
	// unsynchronised access it used to have was a genuine torn-read race. It
	// gets its own mutex so touching a session never queues behind an in-flight
	// write on the connection.
	activeMtx  sync.Mutex
	lastActive time.Time
}

// touch records that the session was used just now.
func (s *session) touch() {
	s.activeMtx.Lock()
	s.lastActive = time.Now()
	s.activeMtx.Unlock()
}

// expired reports whether the session has been idle for longer than timeout.
func (s *session) expired(now time.Time, timeout time.Duration) bool {
	s.activeMtx.Lock()
	defer s.activeMtx.Unlock()
	return !s.lastActive.Add(timeout).After(now)
}

func (s *session) Send(data []byte) error {
	if s.conn == nil {
		return errors.New("WebSocket is null")
	}

	s.mtx.Lock()
	err := s.conn.WriteMessage(websocket.TextMessage, data)
	s.mtx.Unlock()
	return err
}

type sessions struct {
	sync.Map

	// F-161: the connection handler has to consult the session count on every
	// upgrade to enforce the cap, and Count used to walk the whole map.
	count int64
}

// Store adds a session to the set, keyed by the same id Delete removes it by.
func (ss *sessions) Store(s *session) {
	if _, loaded := ss.Map.LoadOrStore(s.id, s); !loaded {
		atomic.AddInt64(&ss.count, 1)
	}
}

func (ss *sessions) Load(id int64) (*session, bool) {
	v, ok := ss.Map.Load(id)
	if !ok {
		// this used to fall through to a type assertion on a nil interface,
		// which panics. No live caller today - hardening only.
		return nil, false
	}
	s, ok := v.(*session)
	return s, ok
}

// Delete is idempotent: a session is torn down both by the sweeper and by the
// connection handler's defer.
func (ss *sessions) Delete(s *session) {
	s.conn.Close()
	if _, loaded := ss.Map.LoadAndDelete(s.id); loaded {
		atomic.AddInt64(&ss.count, -1)
	}
}

func (ss *sessions) Count() int {
	return int(atomic.LoadInt64(&ss.count))
}

func (ss *sessions) Foreach(f func(*session)) {
	ss.Map.Range(func(k, v interface{}) bool {
		f(v.(*session))
		return true
	})
}
