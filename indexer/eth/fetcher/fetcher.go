package fetcher

import (
	"strconv"
	"strings"
	"time"

	"github.com/dynamicgo/slf4go"

	"github.com/openzknetwork/gochain/indexer"

	"github.com/openzknetwork/gochain/rpc/eth"
)

//Handler  .
type Handler interface {
	Block(block *eth.Block, blockNumber int64, blockTime time.Time) error
	TX(tx *eth.Transaction, blockNumber int64, blockTime time.Time) error
}

type fetchImpl struct {
	slf4go.Logger
	client  eth.Client
	handler Handler
}

// New .
func New(ethnode string, handler Handler) indexer.Fetcher {
	return &fetchImpl{
		Logger:  slf4go.Get("eth-fetcher"),
		client:  eth.New(ethnode),
		handler: handler,
	}
}

func (fetcher *fetchImpl) FetchAndHandle(offset int64) (bool, error) {

	fetcher.DebugF("fetch best block number")
	
	bestBlock, err := fetcher.client.BestBlockNumber()

	if err != nil {
		return false, err
	}

	if offset > bestBlock {
		return false, nil
	}

	fetcher.DebugF("get best block by number %d", offset)

	block, err := fetcher.client.GetBlockByNumber(offset)

	if err != nil {
		return false, err
	}

	if block == nil {
		return false, nil
	}

	blockNumber, _ := strconv.ParseUint(strings.TrimPrefix(block.Number, "0x"), 16, 64)

	timestamp, _ := strconv.ParseInt(strings.TrimPrefix(block.Timestamp, "0x"), 16, 64)

	blockTime := time.Unix(timestamp, 0)

	for _, tx := range block.Transactions {
		fetcher.TraceF("handle tx(%s) ", tx.Hash)

		err := fetcher.handler.TX(tx, int64(blockNumber), blockTime)

		if err != nil {
			fetcher.ErrorF("handle tx(%s) err %s", tx.Hash, err)
			return false, err
		}

		fetcher.TraceF("handle tx(%s) -- success", tx.Hash)
	}

	fetcher.TraceF("handle block(%s)", block.Hash)

	if err := fetcher.handler.Block(block, int64(blockNumber), blockTime); err != nil {
		fetcher.ErrorF("handle block(%s) err %s", block.Hash, err)
		return false, err
	}

	fetcher.TraceF("handle block(%s) -- success", block.Hash)

	return true, err
}
