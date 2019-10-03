package fetcher

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/dynamicgo/slf4go"

	"github.com/openzknetwork/gochain/indexer"
	"github.com/tendermint/go-amino"

	"github.com/openzknetwork/gochain/rpc/bnb"
)

//Handler  .
type Handler interface {
	Block(block *bnb.Blocks, blockNumber int64, blockTime time.Time) error
	TX(tx *bnb.Transaction, blockNumber int64, blockTime time.Time) error
}

type fetchImpl struct {
	slf4go.Logger
	client  bnb.Client
	handler Handler
}

// New .
func New(apinode, wsnode string, network int, handler Handler) (indexer.Fetcher, error) {
	client, err := bnb.New(apinode, wsnode, network)
	if err != nil {
		return nil, err
	}
	return &fetchImpl{
		Logger:  slf4go.Get("ont-fetcher"),
		client:  client,
		handler: handler,
	}, nil
}

func (fetcher *fetchImpl) FetchAndHandle(offset int64) (bool, error) {

	fetcher.DebugF("fetch best block number")

	//Notice: 处理 API rate limit exceeded
	time.Sleep(1)

	bestBlock, err := fetcher.client.BestBlockNumber()

	if err != nil {
		return false, err
	}

	if offset > int64(bestBlock) {
		return false, nil
	}

	fetcher.DebugF("get best block by number %d", offset)
	//Notice: 处理 API rate limit exceeded
	time.Sleep(1)

	block, err := fetcher.client.GetBlockByNumber(uint32(offset))

	if err != nil {
		return false, err
	}

	if block == nil {
		return false, nil
	}

	blockNumber, err := strconv.ParseInt(block.Height, 10, 64)
	if err != nil {
		return false, err
	}
	blockTime := block.Time
	codec := amino.NewCodec()

	for _, v := range block.Txs {
		txHash := v.Hash()
		m := new(bnb.StdTx)
		codec.UnmarshalBinaryLengthPrefixed(v, m)
		for k, _ := range m.Msgs {

			if sendMsg, ok := m.Msgs[k].(bnb.SendMsg); ok {
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
			} else if sendMsg, ok := m.Msgs[k].(bnb.CreateOrderMsg); ok {
				// side := sendMsg.Side   -1 buy
				bnbTx := &bnb.Transaction{
					From:     "",
					To:       "",
					Symbol:   sendMsg.Symbol,
					Amount:   int64((float64(sendMsg.Price) * float64(sendMsg.Quantity)) / math.Pow10(8)),
					Tx:       strings.ToUpper(ToHexString(txHash)),
					Block:    blockNumber,
					T:        blockTime,
					GasLimit: 1,
					GasPrice: 37500, //dex 单价
				}
				if sendMsg.Side == -1 {
					bnbTx.From = sendMsg.Sender.String()
				} else {
					bnbTx.To = sendMsg.Sender.String()
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

	fetcher.TraceF("handle block(%d)", block)

	if err := fetcher.handler.Block(block, int64(blockNumber), blockTime); err != nil {
		fetcher.ErrorF("handle block(%d) err %s", block, err)
		return false, err
	}

	fetcher.TraceF("handle block(%d) -- success", block)

	return true, err
}

// ToHexString .
func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}
