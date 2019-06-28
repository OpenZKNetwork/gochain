package fetcher

import (
	"time"

	"github.com/dynamicgo/slf4go"

	"github.com/openzknetwork/gochain/indexer"

	"github.com/openzknetwork/gochain/rpc/ont"
)

//Handler  .
type Handler interface {
	Block(block *ont.Block, blockNumber int64, blockTime time.Time) error
	TX(tx *ont.Transaction, blockNumber int64, blockTime time.Time) error
}

type fetchImpl struct {
	slf4go.Logger
	client  ont.Client
	handler Handler
}

// New .
func New(ontnode string, handler Handler) indexer.Fetcher {
	return &fetchImpl{
		Logger:  slf4go.Get("ont-fetcher"),
		client:  ont.New(ontnode),
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
	blockNumber := block.Header.Height
	blockTime := time.Unix(int64(block.Header.Timestamp), 0)
	for _, tx := range block.Transactions {
		txHash := tx.Hash()
		fetcher.TraceF("handle tx(%s) ", txHash.ToHexString())
		err = fetcher.handler.TX(tx, int64(blockNumber), blockTime)

		if err != nil {
			fetcher.ErrorF("handle tx(%s) err %s", txHash.ToHexString(), err)
			return false, err
		}

		fetcher.TraceF("handle tx(%s) -- success", txHash.ToHexString())
	}

	blockHash := block.Header.Hash()
	fetcher.TraceF("handle block(%s)", blockHash.ToHexString())

	if err := fetcher.handler.Block(block, int64(blockNumber), blockTime); err != nil {
		fetcher.ErrorF("handle block(%s) err %s", blockHash.ToHexString(), err)
		return false, err
	}

	fetcher.TraceF("handle block(%s) -- success", blockHash.ToHexString())

	return true, err
}
