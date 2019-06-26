package ont

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/dynamicgo/slf4go"
)

//SDK .
type SDK struct {
	rpc *RPCImpl //Rpc client used the rpc api of ontology
	// defClient OntologyClient
	qid uint64
	Native *NativeContract
	slf4go.Logger
}



//New return SDK.
func New() *SDK {
	ontSdk := &SDK{}
	native := newNativeContract(ontSdk)
	ontSdk.Native = native
	return ontSdk
}

//NewSdk .
func NewSdk(url string, qid uint64) *SDK {
	return &SDK{
		rpc:    NewRPC(url),
		Logger: slf4go.Get("ont-rpc-client"),
	}
}


//GetCurrentBlockHeight .
func (client *SDK) GetCurrentBlockHeight() (uint32, error) {

	data, err := client.rpc.GetCurrentBlockHeight(client.GetNextQid())
	if err != nil {
		return 0, err
	}
	return GetUint32(data)
}

// GetCurrentBlockHash .
func (client *SDK) GetCurrentBlockHash() (Uint256, error) {

	data, err := client.rpc.GetCurrentBlockHash(client.GetNextQid())
	if err != nil {
		return UINT256_EMPTY, err
	}
	return GetUint256(data)
}

//GetBlockByHeight .
func (client *SDK) GetBlockByHeight(height uint32) (*Block, error) {

	data, err := client.rpc.GetBlockByHeight(client.GetNextQid(), height)
	if err != nil {
		return nil, err
	}
	return GetBlock(data)
}

//GetBlockInfoByHeight .
func (client *SDK) GetBlockInfoByHeight(height uint32) ([]byte, error) {
	data, err := client.rpc.GetBlockInfoByHeight(client.GetNextQid(), height)
	if err != nil {
		return nil, err
	}
	return data, nil
}

//GetBlockByHash .
func (client *SDK) GetBlockByHash(blockHash string) (*Block, error) {
	data, err := client.rpc.GetBlockByHash(client.GetNextQid(), blockHash)
	if err != nil {
		return nil, err
	}
	return GetBlock(data)
}

//GetTransaction .
func (client *SDK) GetTransaction(txHash string) (*Transaction, error) {
	data, err := client.rpc.GetRawTransaction(client.GetNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return GetTransaction(data)
}

//GetBlockHash .
func (client *SDK) GetBlockHash(height uint32) (Uint256, error) {
	data, err := client.rpc.GetBlockHash(client.GetNextQid(), height)
	if err != nil {
		return UINT256_EMPTY, err
	}
	return GetUint256(data)
}

//GetBlockHeightByTxHash .
func (client *SDK) GetBlockHeightByTxHash(txHash string) (uint32, error) {
	data, err := client.rpc.GetBlockHeightByTxHash(client.GetNextQid(), txHash)
	if err != nil {
		return 0, err
	}
	return GetUint32(data)
}

//GetBlockTxHashesByHeight .
func (client *SDK) GetBlockTxHashesByHeight(height uint32) (*BlockTxHashes, error) {
	data, err := client.rpc.GetBlockTxHashesByHeight(client.GetNextQid(), height)
	if err != nil {
		return nil, err
	}
	return GetBlockTxHashes(data)
}

// GetStorage .
func (client *SDK) GetStorage(contractAddress string, key []byte) ([]byte, error) {
	data, err := client.rpc.GetStorage(client.GetNextQid(), contractAddress, key)
	if err != nil {
		return nil, err
	}
	return GetStorage(data)
}

//GetSmartContract .
func (client *SDK) GetSmartContract(contractAddress string) (*SmartContract, error) {
	data, err := client.rpc.GetSmartContract(client.GetNextQid(), contractAddress)
	if err != nil {
		return nil, err
	}
	deployCode, err := GetSmartContract(data)
	if err != nil {
		return nil, err
	}
	sm := SmartContract(*deployCode)
	return &sm, nil
}

//GetSmartContractEvent .
func (client *SDK) GetSmartContractEvent(txHash string) (*SmartContactEvent, error) {
	data, err := client.rpc.GetSmartContractEvent(client.GetNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return GetSmartContractEvent(data)
}

// GetSmartContractEventByBlock .
func (client *SDK) GetSmartContractEventByBlock(height uint32) ([]*SmartContactEvent, error) {
	data, err := client.rpc.GetSmartContractEventByBlock(client.GetNextQid(), height)
	if err != nil {
		return nil, err
	}
	return GetSmartContactEvents(data)
}

//GetMerkleProof .
func (client *SDK) GetMerkleProof(txHash string) (*MerkleProof, error) {
	data, err := client.rpc.GetMerkleProof(client.GetNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return GetMerkleProof(data)
}

//GetMemPoolTxState .
func (client *SDK) GetMemPoolTxState(txHash string) (*MemPoolTxState, error) {
	data, err := client.rpc.GetMemPoolTxState(client.GetNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return GetMemPoolTxState(data)
}

//GetMemPoolTxCount .
func (client *SDK) GetMemPoolTxCount() (*MemPoolTxCount, error) {
	data, err := client.rpc.GetMemPoolTxCount(client.GetNextQid())
	if err != nil {
		return nil, err
	}
	return GetMemPoolTxCount(data)
}

//GetVersion .
func (client *SDK) GetVersion() (string, error) {
	data, err := client.rpc.GetVersion(client.GetNextQid())
	if err != nil {
		return "", err
	}
	return GetVersion(data)
}

// GetNetworkID .
func (client *SDK) GetNetworkID() (uint32, error) {
	data, err := client.rpc.GetNetworkID(client.GetNextQid())
	if err != nil {
		return 0, err
	}
	return GetUint32(data)
}

// SendTransaction .
func (client *SDK) SendTransaction(mutTx *MutableTransaction) (Uint256, error) {
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return UINT256_EMPTY, err
	}
	data, err := client.rpc.SendRawTransaction(client.GetNextQid(), tx, false)
	if err != nil {
		return UINT256_EMPTY, err
	}
	return GetUint256(data)
}

//PreExecTransaction .
func (client *SDK) PreExecTransaction(mutTx *MutableTransaction) (*PreExecResult, error) {
	tx, err := mutTx.IntoImmutable()
	if err != nil {
		return nil, err
	}

	data, err := client.rpc.SendRawTransaction(client.GetNextQid(), tx, true)
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

//WaitForGenerateBlock Wait ontology generate block. Default wait 2 blocks.
//return timeout error when there is no block generate in some time.
func (client *SDK) WaitForGenerateBlock(timeout time.Duration, blockCount ...uint32) (bool, error) {
	count := uint32(2)
	if len(blockCount) > 0 && blockCount[0] > 0 {
		count = blockCount[0]
	}
	blockHeight, err := client.GetCurrentBlockHeight()
	if err != nil {
		return false, fmt.Errorf("GetCurrentBlockHeight error:%s", err)
	}
	secs := int(timeout / time.Second)
	if secs <= 0 {
		secs = 1
	}
	for i := 0; i < secs; i++ {
		time.Sleep(time.Second)
		curBlockHeigh, err := client.GetCurrentBlockHeight()
		if err != nil {
			continue
		}
		if curBlockHeigh-blockHeight >= count {
			return true, nil
		}
	}
	return false, fmt.Errorf("timeout after %d (s)", secs)
}

//GetNextQid .
func (client *SDK) GetNextQid() string {
	return fmt.Sprintf("%d", atomic.AddUint64(&client.qid, 1))
}
