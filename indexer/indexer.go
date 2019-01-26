package indexer

import (
	"context"
	"time"

	"github.com/dynamicgo/xerrors"

	config "github.com/dynamicgo/go-config"
	"github.com/dynamicgo/retry"
	"github.com/dynamicgo/slf4go"
	"github.com/go-xorm/xorm"
)

type indexerImpl struct {
	slf4go.Logger               // mixin logger
	engine        *xorm.Engine  // database
	fetcher       Fetcher       // fetcher
	name          string        // indexer unique name
	backoff       time.Duration //
}

// NewIndexer .
func NewIndexer(config config.Config, fetcher Fetcher) (Indexer, error) {
	logger := slf4go.Get("indexer")

	driver := config.Get("database", "driver").String("sqlite3")
	source := config.Get("database", "source").String("./indexer.db")

	engine, err := xorm.NewEngine(driver, source)

	if err != nil {
		return nil, err
	}

	indexer := &indexerImpl{
		Logger:  logger,
		engine:  engine,
		fetcher: fetcher,
		name:    config.Get("name").String(""),
	}

	if indexer.name == "" {
		return nil, xerrors.Wrapf(ErrParam, "expect indexer name")
	}

	backoff := config.Get("backoff").Duration(time.Second * 20)

	indexer.backoff = backoff

	return indexer, nil
}

func (indexer *indexerImpl) Run() error {
	for {
		indexer.runLoop()
	}
}

func (indexer *indexerImpl) runLoop() {
	action := retry.New(indexer.fetchAndHandle, retry.WithBackoff(indexer.backoff, 1), retry.Infinite())

	defer action.Close()

	for {
		select {
		case <-action.Do():
			return
		case err := <-action.Error():
			indexer.ErrorF("run indexer got error: %s", err)
		}
	}
}

func (indexer *indexerImpl) fetchAndHandle(ctx context.Context) error {

	indexer.DebugF("[%s] get offset", indexer.name)

	offset, err := indexer.getOffset()

	if err != nil {
		return xerrors.Wrapf(err, "[%s] get offset", indexer.name)
	}

	indexer.DebugF("[%s] fetch block %d", indexer.name, offset)

	ok, err := indexer.fetcher.FetchAndHandle(offset)

	if err != nil {
		return xerrors.Wrapf(err, "[%s] fetch block %d error", indexer.name, offset)
	}

	if !ok {
		return xerrors.Wrapf(err, "[%s] fetch block %d -- not found", indexer.name, offset)
	}

	_, err = indexer.updateOffset(offset)

	if err != nil {
		return xerrors.Wrapf(err, "update fetcher offset %d err", offset)
	}

	indexer.DebugF("[%s] fetch block %d -- success", indexer.name, offset)

	return nil
}

func (indexer *indexerImpl) getOffset() (int64, error) {
	t := new(Cursor)

	ok, err := indexer.engine.Where(`"name" = ?`, indexer.name).Get(t)

	if err != nil {
		return 0, xerrors.Wrapf(err, "get offset error")
	}

	if !ok {
		t.Name = indexer.name
		t.Offset = 0
		_, err := indexer.engine.InsertOne(t)

		if err != nil {
			return 0, xerrors.Wrapf(err, "insert offset error")
		}

		return 0, nil
	}

	return t.Offset, nil
}

func (indexer *indexerImpl) updateOffset(old int64) (int64, error) {

	indexer.DebugF("[%s] update block %d", indexer.name, old)

	t := new(Cursor)

	t.Offset = old + 1

	affected, err := indexer.engine.Where(`"name" = ?`, indexer.name).Update(t)

	return affected, err
}
