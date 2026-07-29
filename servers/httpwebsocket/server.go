// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package httpwebsocket

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/servers"
	"github.com/elastos/Elastos.ELA/servers/errors"

	"github.com/gorilla/websocket"
)

const (
	// sessionTimeout is the duration of inactivity before we time out a session.
	sessionTimeout = time.Minute

	// F-162: net/http's ReadTimeout and WriteTimeout must NOT be set on this
	// server. net/http installs those deadlines on the raw connection and they
	// survive the websocket hijack, so they would silently kill every
	// established session. readHeaderTimeout bounds the pre-upgrade request -
	// net/http clears that deadline once the header is read - and idleTimeout
	// only ever applies to a connection that is still HTTP. Both are safe here
	// and both close the Slowloris window the server used to leave wide open.
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 60 * time.Second

	// maxMessageSize bounds one inbound websocket message. F-161: gorilla reads
	// a whole message into memory before returning it and no SetReadLimit was
	// called anywhere, so one unauthenticated client could make the node
	// allocate without bound. The largest legitimate payload here is a raw
	// transaction; the figure matches httpjsonrpc.MaxRPCRead.
	maxMessageSize = 1024 * 1024 * 8

	// defaultMaxSessions bounds concurrent websocket sessions. F-161: sessions
	// were unbounded, and each one costs a connection, a goroutine and a slot in
	// every broadcast.
	defaultMaxSessions = 512
)

var instance *Server

var (
	PushBlockFlag    = true
	PushRawBlockFlag = true
	PushBlockTxsFlag = true
	PushNewTxsFlag   = true
)

type Handler func(servers.Params) map[string]interface{}

type Server struct {
	sync.RWMutex
	*http.Server
	net.Listener
	websocket.Upgrader

	connCount   int64
	sessions    *sessions
	handlers    map[string]Handler
	maxSessions int
}

func Start() {
	instance = &Server{
		Upgrader:    websocket.Upgrader{},
		sessions:    &sessions{},
		maxSessions: defaultMaxSessions,
	}

	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case events.ETBlockConnected:
			SendBlock2WSclient(e.Data)

		case events.ETTransactionAccepted:
			SendTx2Client(e.Data)
		}
	})

	instance.Start()
}

func (s *Server) Start() {
	s.initMethods()
	s.Upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	if config.Parameters.HttpWsPort%1000 == servers.TlsPort {
		var err error
		s.Listener, err = s.initTlsListen()
		if err != nil {
			log.Error("Https Cert: ", err.Error())
		}
	} else {
		var err error
		s.Listener, err = net.Listen("tcp", ":"+strconv.Itoa(config.Parameters.HttpWsPort))
		if err != nil {
			log.Fatal("net.Listen: ", err.Error())
			return
		}
	}
	// Same defect the F-036 fix removed from the REST server, still present
	// here: common/log's Fatal does NOT exit, so both error paths above used to
	// fall through to Serve() with a nil listener and panic - in a bare
	// goroutine, outside net/http's per-connection recover, which takes the
	// whole daemon down.
	if s.Listener == nil {
		log.Error("websocket listener is nil, not serving")
		return
	}
	var done = make(chan bool)
	go s.sessionHandler(done)

	// Publish the server pointer under the same lock Stop reads it with, so a
	// Stop racing a slow Start sees a fully constructed pointer, not a torn one.
	s.Lock()
	s.Server = &http.Server{
		Handler: http.HandlerFunc(s.Handler),
		// F-162: ReadTimeout/WriteTimeout are deliberately left unset here,
		// see the comment on readHeaderTimeout.
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	s.Unlock()
	err := s.Serve(s.Listener)

	done <- true
	if err != nil {
		log.Fatal("ListenAndServe: ", err.Error())
	}
}

func (s *Server) initMethods() {
	s.handlers = map[string]Handler{
		"getconnectioncount": servers.GetConnectionCount,
		"getblockbyheight":   servers.GetBlockByHeight,
		"getblockbyhash":     servers.GetBlockByHash,
		"getblockheight":     servers.GetBlockHeight,
		"gettransaction":     servers.GetTransactionByHash,
		"getasset":           servers.GetAssetByHash,
		"getunspendoutput":   servers.GetUnspendOutput,
		"sendrawtransaction": servers.SendRawTransaction,
		"heartbeat":          s.heartBeat,
		"getsessioncount":    s.getSessionCount,
	}
}

func (s *Server) heartBeat(cmd servers.Params) map[string]interface{} {
	return servers.ResponsePack(errors.Success, "123")
}

func (s *Server) getSessionCount(cmd servers.Params) map[string]interface{} {
	return servers.ResponsePack(errors.Success, s.sessions.Count())
}

func (s *Server) Stop() {
	s.RLock()
	srv := s.Server
	s.RUnlock()
	if srv != nil {
		srv.Shutdown(context.Background())
	}
	log.Info("Close websocket ")
}

func (s *Server) sessionHandler(done chan bool) {
	ticker := time.NewTicker(sessionTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.sessions.Foreach(func(v *session) {
				if !v.expired(now, sessionTimeout) {
					return
				}

				resp := servers.ResponsePack(errors.SessionExpired, "")
				s.response(v, resp)
				s.sessions.Delete(v)
			})

		case <-done:
			return
		}
	}
}

func (s *Server) Handler(w http.ResponseWriter, r *http.Request) {
	// F-161: refuse before the upgrade, so an over-cap client gets a plain HTTP
	// error instead of a websocket that is torn down a moment later.
	//
	// CORRECTION (campaign close-out): the earlier text claimed the concurrent
	// overshoot "is bounded" without saying by what. It is NOT bounded by any
	// constant of ours. Count() and the Upgrade below are not atomic together, so
	// every request already past this check and not yet inserted into s.sessions is
	// invisible here; the overshoot therefore equals the number of upgrades IN
	// FLIGHT, which is set by the ATTACKER's connection concurrency and by
	// net/http's accept rate -- not by maxSessions. A client opening N connections
	// in parallel against a full server can seat close to N extra sessions in that
	// window.
	//
	// Why this is still worth having, stated plainly rather than overstated: the
	// window is one Upgrade long, each overshoot session costs one slot and is
	// reclaimed by the normal expiry sweep, and the cap holds in the steady state.
	// A HARD bound needs the check and the insert under one lock (reserve-then-
	// insert on s.sessions), which is a behaviour change to the session map and is
	// deliberately NOT made here.
	if s.maxSessions > 0 && s.sessions.Count() >= s.maxSessions {
		log.Warn("websocket session limit reached, rejecting connection")
		http.Error(w, "too many websocket sessions",
			http.StatusServiceUnavailable)
		return
	}

	conn, err := s.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("websocket Upgrader: ", err)
		return
	}
	defer conn.Close()

	// F-161: bound one inbound message, see maxMessageSize.
	conn.SetReadLimit(maxMessageSize)

	ss := &session{
		id:         atomic.AddInt64(&s.connCount, 1),
		conn:       conn,
		lastActive: time.Now(),
	}
	s.sessions.Store(ss)

	defer func() {
		s.sessions.Delete(ss)
	}()

	for {
		_, bysMsg, err := conn.ReadMessage()
		if err == nil {
			if s.handle(ss, bysMsg, r) {
				ss.touch()
			}
			continue
		}
		e, ok := err.(net.Error)
		if !ok || !e.Timeout() {
			log.Error("websocket conn:", err)
			return
		}
	}
}

func (s *Server) IsValidMsg(action string, reqMsg map[string]interface{}) bool {
	valid := true
	switch action {
	case "getblockbyheight":
		_, valid = reqMsg["height"]
	case "getblockbyhash":
		_, valid = reqMsg["blockhash"]
	case "gettransaction":
		_, valid = reqMsg["hash"]
	case "getasset":
		_, valid = reqMsg["hash"]
	case "getunspendoutput":
		_, ok1 := reqMsg["addr"]
		_, ok2 := reqMsg["assetid"]
		if ok1 && ok2 {
			valid = true
		} else {
			valid = false
		}
	case "sendrawtransaction":
		_, valid = reqMsg["data"]
	}
	return valid
}

func (s *Server) handle(ss *session, bysMsg []byte, r *http.Request) bool {
	var req = make(map[string]interface{})

	if err := json.Unmarshal(bysMsg, &req); err != nil {
		resp := servers.ResponsePack(errors.IllegalDataFormat, "")
		s.response(ss, resp)
		log.Error("websocket OnDataHandle:", err)
		return false
	}
	action, ok := req["action"].(string)
	if !ok {
		resp := servers.ResponsePack(errors.InvalidMethod, "")
		s.response(ss, resp)
		return false
	}
	handler, ok := s.handlers[action]
	if !ok {
		resp := servers.ResponsePack(errors.InvalidMethod, "")
		s.response(ss, resp)
		return false
	}
	if !s.IsValidMsg(action, req) {
		resp := servers.ResponsePack(errors.InvalidParams, "")
		s.response(ss, resp)
		return true
	}

	resp := handler(req)
	resp["Action"] = action

	s.response(ss, resp)

	return true
}

func (s *Server) response(ss *session, resp map[string]interface{}) {
	resp["Desc"] = errors.ErrMap[resp["Error"].(errors.ServerErrCode)]
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error("Websocket response:", err)
		return
	}
	ss.Send(data)
}

func SendTx2Client(v interface{}) {
	if PushNewTxsFlag {
		go func() {
			instance.PushResult("sendnewtransaction", v)
		}()
	}
}

func SendBlock2WSclient(v interface{}) {
	//if PushBlockFlag {
	//	go func() {
	//		instance.PushResult("sendblock", v)
	//	}()
	//}
	if PushRawBlockFlag {
		go func() {
			instance.PushResult("sendrawblock", v)
		}()
	}
	if PushBlockTxsFlag {
		go func() {
			instance.PushResult("sendblocktransactions", v)
		}()
	}
}

func (s *Server) PushResult(action string, v interface{}) {
	var result interface{}
	switch action {
	case "sendblock", "sendrawblock":
		if block, ok := v.(*types.Block); ok {
			result = servers.GetBlockInfo(block, true)
		}
		//case "sendrawblock":
		//	if block, ok := v.(*Block); ok {
		//		w := bytes.NewBuffer(nil)
		//		block.Serialize(w)
		//		result = BytesToHexString(w.Bytes())
		//	}
	case "sendblocktransactions":
		if block, ok := v.(*types.Block); ok {
			result = servers.GetBlockTransactions(block)
		}
	case "sendnewtransaction":
		if tx, ok := v.(interfaces.Transaction); ok {
			result = servers.GetTransactionContextInfo(nil, tx)
		}
	default:
		log.Error("httpwebsocket/server.go in pushresult function: unknown action")
	}

	resp := servers.ResponsePack(errors.Success, result)
	resp["Action"] = action

	data, err := json.Marshal(resp)
	if err != nil {
		log.Error("Websocket PushResult:", err)
		return
	}

	// Broadcast message to all connected clients.
	s.sessions.Foreach(func(v *session) {
		v.Send(data)
	})
}

func (s *Server) initTlsListen() (net.Listener, error) {

	CertPath := config.Parameters.RestCertPath
	KeyPath := config.Parameters.RestKeyPath

	// load cert
	cert, err := tls.LoadX509KeyPair(CertPath, KeyPath)
	if err != nil {
		log.Error("load keys fail", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	log.Info("TLS listen port is ", strconv.Itoa(config.Parameters.HttpWsPort))
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(config.Parameters.HttpWsPort), tlsConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return listener, nil
}
