// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package httprestful

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/servers"
	. "github.com/elastos/Elastos.ELA/servers/errors"
)

const (
	// IOTimeout bounds reading and writing a REST request. F-162: the REST
	// http.Server set no deadline of any kind, so an idle or dribbling client
	// held its connection - and its goroutine - forever (Slowloris). This is the
	// same budget httpjsonrpc already applies to the very same handlers.
	IOTimeout = 60 * time.Second

	// HeaderTimeout bounds the request line and headers on their own. A client
	// with anything to say has said it well inside this, and it is the deadline
	// that closes the classic Slowloris hold - see IOTimeout.
	HeaderTimeout = 10 * time.Second

	// MaxRESTRead bounds a REST request body. F-149: the POST handler read the
	// body with ioutil.ReadAll and discarded the error, so a single
	// unauthenticated request could allocate without bound. Same figure as
	// httpjsonrpc.MaxRPCRead.
	MaxRESTRead = 1024 * 1024 * 8
)

const (
	ApiGetConnectionCount  = "/api/v1/node/connectioncount"
	ApiGetNodeState        = "/api/v1/node/state"
	ApiGetBlockTxsByHeight = "/api/v1/block/transactions/height/:height"
	ApiGetBlockByHeight    = "/api/v1/block/details/height/:height"
	ApiGetBlockByHash      = "/api/v1/block/details/hash/:hash"
	ApiGetConfirmByHeight  = "/api/v1/confirm/details/height/:height"
	ApiGetConfirmByHash    = "/api/v1/confirm/details/hash/:hash"
	ApiGetBlockHeight      = "/api/v1/block/height"
	ApiGetBlockHash        = "/api/v1/block/hash/:height"
	ApiGetTransaction      = "/api/v1/transaction/:hash"
	ApiGetAsset            = "/api/v1/asset/:hash"
	ApiGetBalanceByAddr    = "/api/v1/asset/balances/:addr"
	ApiGetBalanceByAsset   = "/api/v1/asset/balance/:addr/:assetid"
	ApiGetUTXOByAsset      = "/api/v1/asset/utxo/:addr/:assetid"
	ApiGetUTXOByAddr       = "/api/v1/asset/utxos/:addr"
	ApiSendRawTransaction  = "/api/v1/transaction"
	ApiGetTransactionPool  = "/api/v1/transactionpool"
)

type Action struct {
	sync.RWMutex
	name    string
	handler func(servers.Params) map[string]interface{}
}

type restServer struct {
	router   *Router
	listener net.Listener
	// serverMtx publishes server to Stop(): Start() runs at boot and Stop() from
	// an RPC handler, so the pointer must not be read while it is being written.
	serverMtx sync.Mutex
	server    *http.Server
	postMap   map[string]Action
	getMap    map[string]Action
}

type ApiServer interface {
	Start()
	Stop()
}

func StartServer() {
	rest := InitRestServer()
	rest.Start()
}

func InitRestServer() ApiServer {
	rt := &restServer{}
	rt.router = &Router{}
	rt.initializeMethod()
	rt.initGetHandler()
	rt.initPostHandler()
	return rt
}

func (rt *restServer) Start() {
	// F-036: log.Fatal does NOT exit in this codebase (common/log/log.go Fatal only
	// writes a line), so every error path below used to fall through to
	// Serve(rt.listener) with a nil listener and panic. On the restart path that
	// panic runs in a bare goroutine outside net/http's per-connection recover, so
	// it killed the whole daemon. Return on every failure and hard-guard Serve.
	if config.Parameters.HttpRestPort == 0 {
		log.Error("Not configure HttpRestPort port ")
		return
	}

	if config.Parameters.HttpRestPort%1000 == servers.TlsPort {
		var err error
		rt.listener, err = rt.initTlsListen()
		if err != nil {
			log.Error("Https Cert: ", err.Error())
			return
		}
	} else {
		var err error
		rt.listener, err = net.Listen("tcp", ":"+strconv.Itoa(config.Parameters.HttpRestPort))
		if err != nil {
			log.Error("net.Listen: ", err.Error())
			return
		}
	}
	if rt.listener == nil {
		log.Error("restful listener is nil, not serving")
		return
	}
	rt.serverMtx.Lock()
	rt.server = &http.Server{
		Handler: rt.router,
		// F-162: see IOTimeout.
		ReadTimeout:       IOTimeout,
		ReadHeaderTimeout: HeaderTimeout,
		WriteTimeout:      IOTimeout,
		IdleTimeout:       IOTimeout,
	}
	rt.serverMtx.Unlock()
	err := rt.server.Serve(rt.listener)

	if err != nil {
		log.Fatal("ListenAndServe: ", err.Error())
	}
}

func (rt *restServer) initializeMethod() {

	getMethodMap := map[string]Action{
		ApiGetConnectionCount:  {name: "getconnectioncount", handler: servers.GetConnectionCount},
		ApiGetNodeState:        {name: "getnodestate", handler: servers.GetNodeState},
		ApiGetBlockTxsByHeight: {name: "getblocktransactionsbyheight", handler: servers.GetTransactionsByHeight},
		ApiGetBlockByHeight:    {name: "getblockbyheight", handler: servers.GetBlockByHeight},
		ApiGetBlockByHash:      {name: "getblockbyhash", handler: servers.GetBlockByHash},
		ApiGetConfirmByHeight:  {name: "getconfirmbyheight", handler: servers.GetConfirmByHeight},
		ApiGetConfirmByHash:    {name: "getconfirmbyhash", handler: servers.GetConfirmByHeight},
		ApiGetBlockHeight:      {name: "getblockheight", handler: servers.GetBlockHeight},
		ApiGetBlockHash:        {name: "getblockhash", handler: servers.GetBlockHash},
		ApiGetTransactionPool:  {name: "gettransactionpool", handler: servers.GetTransactionPool},
		ApiGetTransaction:      {name: "gettransaction", handler: servers.GetTransactionByHash},
		ApiGetAsset:            {name: "getasset", handler: servers.GetAssetByHash},
		ApiGetUTXOByAddr:       {name: "getutxobyaddr", handler: servers.GetUnspends},
		ApiGetUTXOByAsset:      {name: "getutxobyasset", handler: servers.GetUnspendOutput},
		ApiGetBalanceByAddr:    {name: "getbalancebyaddr", handler: servers.GetBalanceByAddr},
		ApiGetBalanceByAsset:   {name: "getbalancebyasset", handler: servers.GetBalanceByAsset},
	}

	postMethodMap := map[string]Action{
		ApiSendRawTransaction: {name: "sendrawtransaction", handler: servers.SendRawTransaction},
	}
	rt.postMap = postMethodMap
	rt.getMap = getMethodMap
}

func (rt *restServer) getPath(url string) string {

	if strings.Contains(url, strings.TrimRight(ApiGetBlockTxsByHeight, ":height")) {
		return ApiGetBlockTxsByHeight
	} else if strings.Contains(url, strings.TrimRight(ApiGetBlockByHeight, ":height")) {
		return ApiGetBlockByHeight
	} else if strings.Contains(url, strings.TrimRight(ApiGetBlockByHash, ":hash")) {
		return ApiGetBlockByHash
	} else if strings.Contains(url, strings.TrimRight(ApiGetConfirmByHeight, ":height")) {
		return ApiGetConfirmByHeight
	} else if strings.Contains(url, strings.TrimRight(ApiGetConfirmByHash, ":hash")) {
		return ApiGetConfirmByHash
	} else if strings.Contains(url, strings.TrimRight(ApiGetBlockHash, ":height")) {
		return ApiGetBlockHash
	} else if strings.Contains(url, strings.TrimRight(ApiGetTransaction, ":hash")) {
		return ApiGetTransaction
	} else if strings.Contains(url, strings.TrimRight(ApiGetBalanceByAddr, ":addr")) {
		return ApiGetBalanceByAddr
	} else if strings.Contains(url, strings.TrimRight(ApiGetBalanceByAsset, ":addr/:assetid")) {
		return ApiGetBalanceByAsset
	} else if strings.Contains(url, strings.TrimRight(ApiGetUTXOByAddr, ":addr")) {
		return ApiGetUTXOByAddr
	} else if strings.Contains(url, strings.TrimRight(ApiGetUTXOByAsset, ":addr/:assetid")) {
		return ApiGetUTXOByAsset
	} else if strings.Contains(url, strings.TrimRight(ApiGetAsset, ":hash")) {
		return ApiGetAsset
	}
	return url
}

func (rt *restServer) getParams(r *http.Request, url string, req map[string]interface{}) map[string]interface{} {
	switch url {
	case ApiGetConnectionCount:

	case ApiGetNodeState:

	case ApiGetBlockTxsByHeight:
		req["height"] = getParam(r, "height")

	case ApiGetBlockByHeight:
		req["height"] = getParam(r, "height")

	case ApiGetBlockByHash:
		req["blockhash"] = getParam(r, "hash")

	case ApiGetConfirmByHeight:
		req["height"] = getParam(r, "height")

	case ApiGetConfirmByHash:
		req["blockhash"] = getParam(r, "hash")

	case ApiGetBlockHeight:

	case ApiGetTransactionPool:

	case ApiGetBlockHash:
		req["height"] = getParam(r, "height")

	case ApiGetTransaction:
		req["hash"] = getParam(r, "hash")

	case ApiGetAsset:
		req["hash"] = getParam(r, "hash")

	case ApiGetBalanceByAsset:
		req["addr"] = getParam(r, "addr")
		req["assetid"] = getParam(r, "assetid")

	case ApiGetBalanceByAddr:
		req["addr"] = getParam(r, "addr")

	case ApiGetUTXOByAddr:
		req["addr"] = getParam(r, "addr")

	case ApiGetUTXOByAsset:
		req["addr"] = getParam(r, "addr")
		req["assetid"] = getParam(r, "assetid")

	case ApiSendRawTransaction:

	}
	return req
}

func (rt *restServer) initGetHandler() {

	for k, _ := range rt.getMap {
		rt.router.Get(k, func(w http.ResponseWriter, r *http.Request) {

			var req = make(map[string]interface{})
			var resp map[string]interface{}

			url := rt.getPath(r.URL.Path)

			if h, ok := rt.getMap[url]; ok {
				req = rt.getParams(r, url, req)
				resp = h.handler(req)
			} else {
				resp = servers.ResponsePack(InvalidMethod, "")
			}
			rt.response(w, resp)
		})
	}
}

func (rt *restServer) initPostHandler() {
	for k, _ := range rt.postMap {
		rt.router.Post(k, func(w http.ResponseWriter, r *http.Request) {

			// F-149: bound the body, and stop discarding the read error.
			body, err := ioutil.ReadAll(
				http.MaxBytesReader(w, r.Body, MaxRESTRead))
			defer r.Body.Close()

			var req = make(map[string]interface{})
			var resp map[string]interface{}

			if err != nil {
				log.Warn("[REST] request body rejected: ", err)
				rt.response(w, servers.ResponsePack(IllegalDataFormat, ""))
				return
			}

			url := rt.getPath(r.URL.Path)
			if h, ok := rt.postMap[url]; ok {
				if err := json.Unmarshal(body, &req); err == nil {
					req = rt.getParams(r, url, req)
					resp = h.handler(req)
				} else {
					resp = servers.ResponsePack(IllegalDataFormat, "")
				}
			} else {
				resp = servers.ResponsePack(InvalidMethod, "")
			}
			rt.response(w, resp)
		})
	}
	//Options
	for k, _ := range rt.postMap {
		rt.router.Options(k, func(w http.ResponseWriter, r *http.Request) {
			rt.write(w, []byte{})
		})
	}

}

func (rt *restServer) write(w http.ResponseWriter, data []byte) {
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("content-type", "application/json;charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

func (rt *restServer) response(w http.ResponseWriter, resp map[string]interface{}) {
	resp["Desc"] = ErrMap[resp["Error"].(ServerErrCode)]
	data, err := json.Marshal(resp)
	if err != nil {
		log.Fatal("HTTP Handle - json.Marshal: %v", err)
		return
	}
	rt.write(w, data)
}

func (rt *restServer) Stop() {
	rt.serverMtx.Lock()
	srv := rt.server
	rt.serverMtx.Unlock()
	if srv != nil {
		srv.Shutdown(context.Background())
		log.Error("Close restful ")
	}
}

func (rt *restServer) Restart(cmd servers.Params) map[string]interface{} {
	go func() {
		rt.Stop()
		rt.Start()
	}()

	return servers.ResponsePack(Success, "")
}

func (rt *restServer) initTlsListen() (net.Listener, error) {

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

	log.Info("TLS listen port is ", strconv.Itoa(config.Parameters.HttpRestPort))
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(config.Parameters.HttpRestPort), tlsConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return listener, nil
}
