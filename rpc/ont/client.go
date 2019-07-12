package ont

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openzknetwork/gochain/script/neo/script"

	"github.com/dynamicgo/slf4go"
)

// Client eth web3 api client
type Client interface {
	// Nonce(address string) (uint64, error)
	GetBalance(address string, asset string) (uint64, error)
	BestBlockNumber() (uint32, error)
	GetBlockByNumber(number uint32) (val *Block, err error)
	GetTransactionByHash(tx string) (val *Transaction, err error)
	SendRawTransaction(tx []byte) (string, error)
	BalanceOfAsset(address string, asset string) (uint64, error)
	// DecimalsOfAsset(asset string) (int, error)
	GetTransactionReceipt(tx string) (val *SmartContactEvent, err error)
	SuggestGasPrice() (uint32, error)
	Decimals() (uint64, error)
	TotalSupply() (uint64, error)
	Symbol() (string, error)
	// Transfer(gasPrice, gasLimit uint64, from *Account, to Address, amount uint64) (string, error)
}

type clientImpl struct {
	qid uint64
	slf4go.Logger
	httpClient *http.Client
	addr       string
	idMux      sync.Mutex
}

//New return RPCImpl instance
func New(url string) Client {
	return &clientImpl{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false, //enable keepalive
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
			},
			Timeout: time.Second * 300, //timeout for http response
		},
		addr:   url,
		Logger: slf4go.Get("eth-rpc-client"),
		qid:    0,
	}
}

//Symbol .
func (client *clientImpl) Symbol() (string, error) {
	preResult, err := client.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (client *clientImpl) GetBalance(address string, asset string) (uint64, error) {
	addr, err := AddressFromBase58(address)
	if err != nil {
		return 0, err
	}
	assetAddress, err := AddressFromHexString(asset)
	if err != nil {
		return 0, err
	}
	preResult, err := client.PreExecInvokeNativeContract(
		assetAddress,
		ONT_CONTRACT_VERSION,
		BALANCEOF_NAME,
		[]interface{}{addr[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (client *clientImpl) BalanceOfAsset(address string, asset string) (uint64, error) {
	addr, err := AddressFromBase58(address)
	if err != nil {
		return 0, err
	}
	invokeCode, err := script.New(address).NewNeoVMScript(asset, []interface{}{"balanceOf", []interface{}{addr}})
	invokePayload := &InvokeCode{
		Code: invokeCode,
	}
	mutTx := &MutableTransaction{
		GasPrice: 0,
		GasLimit: 0,
		TxType:   Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]Sig, 0, 0),
	}
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return 0, err
	}

	var buffer bytes.Buffer
	err = tx.Serialize(&buffer)
	if err != nil {
		return 0, fmt.Errorf("serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	params := []interface{}{txData}
	data, err := client.sendRequest(sendTransaction, params)
	if err != nil {
		return 0, err
	}
	preResult := &PreExecResult{}
	err = json.Unmarshal(data, &preResult)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal PreExecResult:%s error:%s", data, err)
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (client *clientImpl) Decimals() (uint64, error) {
	preResult, err := client.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return decimals.Uint64(), nil
}

func (client *clientImpl) TotalSupply() (uint64, error) {
	preResult, err := client.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (client *clientImpl) GetTransactionReceipt(txHash string) (*SmartContactEvent, error) {
	data, err := client.sendRequest(getSmartCodeEvent, []interface{}{txHash})
	if err != nil {
		return nil, err
	}
	return GetSmartContractEvent(data)
}
func (client *clientImpl) GetBlockByNumber(height uint32) (*Block, error) {
	data, err := client.sendRequest(getBlock, []interface{}{height})
	if err != nil {
		return nil, err
	}
	return GetBlock(data)
}

func (client *clientImpl) SuggestGasPrice() (uint32, error) {
	data, err := client.sendRequest(getGasPrice, []interface{}{})
	if err != nil {
		return 0, err
	}
	return GetUint32(data)
}

func (client *clientImpl) GetTransactionByHash(txHash string) (*Transaction, error) {
	data, err := client.sendRequest(getTransaction, []interface{}{txHash})
	if err != nil {
		return nil, err
	}
	return GetTransaction(data)
}

func (client *clientImpl) BestBlockNumber() (uint32, error) {
	data, err := client.sendRequest(getBlockCount, []interface{}{})
	if err != nil {
		return 0, err
	}
	count, err := GetUint32(data)
	if err != nil {
		return 0, err
	}
	b, err := json.Marshal(count - 1)
	if err != nil {
		return 0, err
	}

	return GetUint32(b)
}

//GetRawTransactionParams .
func (client *clientImpl) GetRawTransactionParams(tx *Transaction, isPreExec bool) ([]interface{}, error) {
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
	return params, nil
}

func (client *clientImpl) Transfer(gasPrice, gasLimit uint64, from *Account, to Address, amount uint64) (string, error) {
	tx, err := client.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return "", err
	}
	err = client.SignToTransaction(tx, from)
	if err != nil {
		return "", err
	}
	mutTx, err := tx.IntoImmutable()
	if err != nil {
		return "", err
	}
	rawparams, err := client.GetRawTransactionParams(mutTx, false)
	if err != nil {
		return "", err
	}
	data, err := client.sendRequest(sendTransaction, rawparams)
	if err != nil {
		return "", err
	}
	res, err := GetUint256(data)
	if err != nil {
		return "", err
	}

	return res.ToHexString(), nil
}
func (client *clientImpl) SendRawTransaction(tx []byte) (string, error) {
	txData := hex.EncodeToString(tx)
	rawParams := []interface{}{txData}
	data, err := client.sendRequest(sendTransaction, rawParams)
	if err != nil {
		return "", err
	}
	res, err := GetUint256(data)
	if err != nil {
		return "", err
	}

	return res.ToHexString(), nil
}
func (client *clientImpl) NewTransferTransaction(gasPrice, gasLimit uint64, from, to Address, amount uint64) (*MutableTransaction, error) {
	state := &State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return client.NewMultiTransferTransaction(gasPrice, gasLimit, []*State{state})
}
func (client *clientImpl) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*State) (*MutableTransaction, error) {
	return client.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_CONTRACT_VERSION,
		ONT_CONTRACT_ADDRESS,
		TRANSFER_NAME,
		[]interface{}{states})
}
func (client *clientImpl) PreExecInvokeNativeContract(
	contractAddress Address,
	version byte,
	method string,
	params []interface{},
) (*PreExecResult, error) {
	tx, err := client.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return client.PreExecTransaction(tx)
}

// NewNativeInvokeTransaction .
func (client *clientImpl) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress Address,
	method string,
	params []interface{},
) (*MutableTransaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := BuildNativeInvokeCode(contractAddress, version, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return client.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

//NewInvokeTransaction return smart contract invoke transaction
func (client *clientImpl) NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *MutableTransaction {
	invokePayload := &InvokeCode{
		Code: invokeCode,
	}
	tx := &MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]Sig, 0, 0),
	}
	return tx
}
func (client *clientImpl) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	version byte,
	contractAddress Address,
	method string,
	params []interface{},
) (Uint256, error) {
	mutTx, err := client.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return UINT256_EMPTY, err
	}
	err = client.SignToTransaction(mutTx, singer)
	if err != nil {
		return UINT256_EMPTY, err
	}
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return UINT256_EMPTY, err
	}
	rawparams, err := client.GetRawTransactionParams(tx, false)
	if err != nil {
		return UINT256_EMPTY, err
	}

	data, err := client.sendRequest(sendTransaction, rawparams)
	if err != nil {
		return UINT256_EMPTY, err
	}
	return GetUint256(data)
}
func (client *clientImpl) SignToTransaction(tx *MutableTransaction, signer Signer) error {
	if tx.Payer == ADDRESS_EMPTY {
		account, ok := signer.(*Account)
		if ok {
			tx.Payer = account.Address
		}
	}
	for _, sigs := range tx.Sigs {
		if PubKeysEqual([]PublicKey{signer.GetPublicKey()}, sigs.PubKeys) {
			//have already signed
			return nil
		}
	}
	txHash := tx.Hash()
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	if tx.Sigs == nil {
		tx.Sigs = make([]Sig, 0)
	}
	tx.Sigs = append(tx.Sigs, Sig{
		PubKeys: []PublicKey{signer.GetPublicKey()},
		M:       1,
		SigData: [][]byte{sigData},
	})
	return nil
}

//PreExecTransaction .
func (client *clientImpl) PreExecTransaction(mutTx *MutableTransaction) (*PreExecResult, error) {
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return nil, err
	}

	rawparams, err := client.GetRawTransactionParams(tx, false)
	if err != nil {
		return nil, err
	}

	data, err := client.sendRequest(sendTransaction, rawparams)
	if err != nil {
		return nil, err
	}

	preResult := &PreExecResult{}
	err = json.Unmarshal(data, &preResult)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal PreExecResult:%s error:%s", data, err)
	}
	return preResult, nil
}

//GetNextQid .
func (client *clientImpl) GetNextQid() string {
	return fmt.Sprintf("%d", atomic.AddUint64(&client.qid, 1))
}

//sendRequest send Rpc request to ontology
func (client *clientImpl) sendRequest(method string, params []interface{}) ([]byte, error) {
	client.idMux.Lock()
	client.qid++
	client.idMux.Unlock()
	rpcReq := &JSONReqest{
		Version: jsonRPCVersion,
		ID:      client.GetNextQid(),
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
