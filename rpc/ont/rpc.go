/*
 * Copyright (C) 2018 The ontology Authors
 * client file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package ont

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	//getVersion .
	getVersion = "getversion"
	//getTransaction .
	getTransaction = "getrawtransaction"
	//sendTransaction .
	sendTransaction = "sendrawtransaction"
	// getBlock .
	getBlock = "getblock"
	//getBlockCount .
	getBlockCount = "getblockcount"
	//getBlockHash .
	getBlockHash = "getblockhash"
	//getCurrentBlockHash .
	getCurrentBlockHash = "getbestblockhash"
	// getBalance .
	getBalance = "getbalance"
	//getSmartCodeEvent .
	getSmartCodeEvent = "getsmartcodeevent"
	//getstorage .
	getStorage = "getstorage"
	//getSmartContract .
	getSmartContract = "getcontractstate"
	//getGenerateBlockTime .
	getGenerateBlockTime = "getgenerateblocktime"
	//getMerkleProof .
	getMerkleProof = "getmerkleproof"
	//getNetworkID .
	getNetworkID = "getnetworkid"
	//getMemPoolTxCount .
	getMemPoolTxCount = "getmempooltxcount"
	//getMemPoolTxState
	getMemPoolTxState = "getmempooltxstate"
	//getBlockTxHashByHegiht
	getBlockTxHashByHegiht = "getblocktxsbyheight"
	//getBlockHeightByTxHash
	getBlockHeightByTxHash = "getblockheightbytxhash"
	//sendEmergencyGovReq
	sendEmergencyGovReq = "sendemergencygovreq"
	//getBlockRootWhitNewTxRoot
	getBlockRootWhitNewTxRoot = "getblockrootwithnewtxroot"
)

//JsonRpc version
const jsonRPCVersion = "2.0"

//JSONResponse object response for JsonRpcRequest
type JSONResponse struct {
	ID     string          `json:"id"`
	Error  int64           `json:"error"`
	Desc   string          `json:"desc"`
	Result json.RawMessage `json:"result"`
}

//JSONReqest object in rpc
type JSONReqest struct {
	Version string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

//RPCImpl for ontology rpc api
type RPCImpl struct {
	addr       string
	httpClient *http.Client
}

//NewRPC return RPCImpl instance
func NewRPC(url string) *RPCImpl {
	return &RPCImpl{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false, //enable keepalive
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
			},
			Timeout: time.Second * 300, //timeout for http response
		},
		addr: url,
	}
}

//GetVersion return the version of ontology
func (client *RPCImpl) GetVersion(qid string) ([]byte, error) {
	return client.sendRequest(qid, getVersion, []interface{}{})
}

//GetNetworkID .
func (client *RPCImpl) GetNetworkID(qid string) ([]byte, error) {
	return client.sendRequest(qid, getNetworkID, []interface{}{})
}

//GetBlockByHash return block with specified block hash in hex string code
func (client *RPCImpl) GetBlockByHash(qid, hash string) ([]byte, error) {
	return client.sendRequest(qid, getBlock, []interface{}{hash})
}

//GetBlockByHeight return block by specified block height
func (client *RPCImpl) GetBlockByHeight(qid string, height uint32) ([]byte, error) {
	return client.sendRequest(qid, getBlock, []interface{}{height})
}

// GetBlockInfoByHeight .
func (client *RPCImpl) GetBlockInfoByHeight(qid string, height uint32) ([]byte, error) {
	return client.sendRequest(qid, getBlock, []interface{}{height, 1})
}

//GetBlockCount return the total block count of ontology
func (client *RPCImpl) GetBlockCount(qid string) ([]byte, error) {
	return client.sendRequest(qid, getBlockCount, []interface{}{})
}

//GetCurrentBlockHeight .
func (client *RPCImpl) GetCurrentBlockHeight(qid string) ([]byte, error) {
	data, err := client.GetBlockCount(qid)
	if err != nil {
		return nil, err
	}
	count, err := GetUint32(data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(count - 1)
}

//GetCurrentBlockHash return the current block hash of ontology
func (client *RPCImpl) GetCurrentBlockHash(qid string) ([]byte, error) {
	return client.sendRequest(qid, getCurrentBlockHash, []interface{}{})
}

//GetBlockHash return block hash by block height
func (client *RPCImpl) GetBlockHash(qid string, height uint32) ([]byte, error) {
	return client.sendRequest(qid, getBlockHash, []interface{}{height})
}

//GetStorage return smart contract storage item.
//addr is smart contact address
//key is the key of value in smart contract
func (client *RPCImpl) GetStorage(qid, contractAddress string, key []byte) ([]byte, error) {
	return client.sendRequest(qid, getStorage, []interface{}{contractAddress, hex.EncodeToString(key)})
}

//GetSmartContractEvent return smart contract event execute by invoke transaction by hex string code
func (client *RPCImpl) GetSmartContractEvent(qid, txHash string) ([]byte, error) {
	return client.sendRequest(qid, getSmartCodeEvent, []interface{}{txHash})
}

//GetSmartContractEventByBlock .
func (client *RPCImpl) GetSmartContractEventByBlock(qid string, blockHeight uint32) ([]byte, error) {
	return client.sendRequest(qid, getSmartCodeEvent, []interface{}{blockHeight})
}

//GetRawTransaction return transaction by transaction hash
func (client *RPCImpl) GetRawTransaction(qid, txHash string) ([]byte, error) {
	return client.sendRequest(qid, getTransaction, []interface{}{txHash})
}

//GetSmartContract return smart contract deployed in ontology by specified smart contract address
func (client *RPCImpl) GetSmartContract(qid, contractAddress string) ([]byte, error) {
	return client.sendRequest(qid, getSmartContract, []interface{}{contractAddress})
}

//GetMerkleProof return the merkle proof whether tx is exist in ledger. Param txHash is in hex string code
func (client *RPCImpl) GetMerkleProof(qid, txHash string) ([]byte, error) {
	return client.sendRequest(qid, getMerkleProof, []interface{}{txHash})
}

//GetMemPoolTxState .
func (client *RPCImpl) GetMemPoolTxState(qid, txHash string) ([]byte, error) {
	return client.sendRequest(qid, getMemPoolTxState, []interface{}{txHash})
}

//GetMemPoolTxCount .
func (client *RPCImpl) GetMemPoolTxCount(qid string) ([]byte, error) {
	return client.sendRequest(qid, getMemPoolTxCount, []interface{}{})
}

// GetBlockHeightByTxHash .
func (client *RPCImpl) GetBlockHeightByTxHash(qid, txHash string) ([]byte, error) {
	return client.sendRequest(qid, getBlockHeightByTxHash, []interface{}{txHash})
}

//GetBlockTxHashesByHeight .
func (client *RPCImpl) GetBlockTxHashesByHeight(qid string, height uint32) ([]byte, error) {
	return client.sendRequest(qid, getBlockTxHashByHegiht, []interface{}{height})
}

//SendRawTransaction .
func (client *RPCImpl) SendRawTransaction(qid string, tx *Transaction, isPreExec bool) ([]byte, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	params := []interface{}{txData}
	if isPreExec {
		params = append(params, 1)
	}
	return client.sendRequest(qid, sendTransaction, params)
}

//sendRequest send Rpc request to ontology
func (client *RPCImpl) sendRequest(qid, method string, params []interface{}) ([]byte, error) {
	rpcReq := &JSONReqest{
		Version: jsonRPCVersion,
		ID:      qid,
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("JsonRpcRequest json.Marsha error:%s", err)
	}
	resp, err := client.httpClient.Post(client.addr, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response body error:%s", err)
	}
	rpcRsp := &JSONResponse{}
	err = json.Unmarshal(body, rpcRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal JsonRpcResponse:%s error:%s", body, err)
	}
	if rpcRsp.Error != 0 {
		return nil, fmt.Errorf("JsonRpcResponse error code:%d desc:%s result:%s", rpcRsp.Error, rpcRsp.Desc, rpcRsp.Result)
	}
	return rpcRsp.Result, nil
}