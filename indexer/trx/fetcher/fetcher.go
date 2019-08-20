package fetcher

import (
	"encoding/hex"
	"time"

	"github.com/dynamicgo/slf4go"

	"github.com/openzknetwork/gochain/indexer"

	"github.com/openzknetwork/gochain/rpc/trx"
)

const (
	trxTransferContract      = "TransferContract"
	trxTransferAssetContract = "TransferAssetContract"
	trxSuccess               = "SUCCESS"
	trxAddress               = ""
)

//Handler  .
type Handler interface {
	Block(block *trx.Block, blockNumber int64, blockTime time.Time) error
	TX(tx *trx.Transaction, blockNumber int64, blockTime time.Time) error
}

type fetchImpl struct {
	slf4go.Logger
	client  trx.Client
	handler Handler
}

// New .
func New(trxnode string, handler Handler) indexer.Fetcher {
	return &fetchImpl{
		Logger:  slf4go.Get("trx-fetcher"),
		client:  trx.New(trxnode),
		handler: handler,
	}
}

func (fetcher *fetchImpl) FetchAndHandle(offset int64) (bool, error) {

	fetcher.DebugF("fetch best block number")

	bestBlock, err := fetcher.client.BestBlockNumber()

	if err != nil {
		return false, err
	}

	if offset > int64(bestBlock) {
		return false, nil
	}

	fetcher.DebugF("get best block by number %d", offset)

	block, err := fetcher.client.GetBlockByNumber(uint32(offset))

	if err != nil {
		return false, err
	}

	if block == nil {
		return false, nil
	}

	blockNumber := block.BlockHeader.RawData.Number
	blockTime := time.Unix(int64(block.BlockHeader.RawData.Timestamp), 0)
	for _, v := range block.Transactions {
		txHash := v.TxID
		for _, val := range v.RawData.Contract {
			if val.Type == trxTransferContract || val.Type == trxTransferAssetContract {
				if val.Parameter.Value.ContractAddress == "" {
					val.Parameter.Value.ContractAddress = trx.TrxPrefix
				} else {
					contractAddress, err := hex.DecodeString(val.Parameter.Value.ContractAddress)
					if err != nil {
						return false, err
					}
					val.Parameter.Value.ContractAddress = trx.TrxPrefix + string(contractAddress)
				}
				tx := &trx.Transaction{
					ParameterValue: val.Parameter.Value,
					TxID:           v.TxID,
					State:          v.Ret[0].ContractRet,
					TxType:         val.Type,
				}
				err = fetcher.handler.TX(tx, int64(blockNumber), blockTime)
				if err != nil {
					fetcher.ErrorF("handle tx(%s) err %s", txHash, err)
					return false, err
				}
			}
		}
		fetcher.TraceF("handle tx(%s) -- success", txHash)
	}

	blockHash := block.BlockID
	fetcher.TraceF("handle block(%s)", blockHash)

	if err := fetcher.handler.Block(block, int64(blockNumber), blockTime); err != nil {
		fetcher.ErrorF("handle block(%s) err %s", blockHash, err)
		return false, err
	}

	fetcher.TraceF("handle block(%s) -- success", blockHash)

	return true, err
}

// ToHexString .
func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}
