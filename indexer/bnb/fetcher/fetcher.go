package fetcher

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/binance-chain/go-sdk/types"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/dynamicgo/slf4go"

	ctypestx "github.com/binance-chain/go-sdk/types/tx"
	"github.com/openzknetwork/gochain/indexer"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"

	"github.com/openzknetwork/gochain/rpc/bnb"
)

//Handler  .
type Handler interface {
	Block(block *ctypes.ResultBlock, blockNumber int64, blockTime time.Time) error
	TX(tx *bnb.Transaction, blockNumber int64, blockTime time.Time) error
}

type fetchImpl struct {
	slf4go.Logger
	client  bnb.Client
	handler Handler
}

// New .
func New(apinode, wsnode string, network int, handler Handler) indexer.Fetcher {
	return &fetchImpl{
		Logger:  slf4go.Get("ont-fetcher"),
		client:  bnb.New(apinode, apinode, network),
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

	blockNumber := block.BlockMeta.Header.Height
	blockTime := block.BlockMeta.Header.Time
	codec := types.NewCodec()
	for _, v := range block.Block.Txs {
		txHash := v.Hash()

		m := new(ctypestx.StdTx)
		codec.UnmarshalBinaryLengthPrefixed(v, m)
		sendMsg, ok := m.Msgs[0].(msg.SendMsg)
		if !ok {
			continue
		}
		for _, v := range sendMsg.Outputs {

			for _, val := range v.Coins {
				bnbTx := &bnb.Transaction{
					From:     sendMsg.Inputs[0].Address.String(),
					To:       v.Address.String(),
					Symbol:   strings.ToLower(val.Denom),
					Amount:   val.Amount,
					Tx:       strings.ToUpper(ToHexString(txHash)),
					Block:    blockNumber,
					T:        blockTime,
					GasLimit: 1,
					GasPrice: 37500, //transfer 固定 0.000375 BNB    https://docs.binance.org/trading-spec.html#current-fees-table-on-mainnet
				}

				err = fetcher.handler.TX(bnbTx, int64(blockNumber), blockTime)

				if err != nil {
					fetcher.ErrorF("handle tx(%s) err %s", ToHexString(txHash), err)
					return false, err
				}

			}

		}
		fetcher.TraceF("handle tx(%s) -- success", ToHexString(txHash))
	}

	blockHash := block.BlockMeta.Header.Hash()
	fetcher.TraceF("handle block(%s)", ToHexString(blockHash))

	if err := fetcher.handler.Block(block, int64(blockNumber), blockTime); err != nil {
		fetcher.ErrorF("handle block(%s) err %s", ToHexString(blockHash), err)
		return false, err
	}

	fetcher.TraceF("handle block(%s) -- success", ToHexString(blockHash))

	return true, err
}

// ToHexString .
func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}
