package indexer

import (
	"errors"
)

// errors .
var (
	ErrParam = errors.New("config or param invalid")
)

// Cursor .
type Cursor struct {
	Name   string `xorm:"pk"`
	Offset int64  `xorm:""`
}

// TableName .
func (cursor *Cursor) TableName() string {
	return "gochain_watcher_cursor"
}

// Indexer .
type Indexer interface {
	Run() error
}

// Fetcher the block indexer fetcher
type Fetcher interface {
	FetchAndHandle(offset int64) (bool, error)
}

// // FetcherF .
// type FetcherF func(config config.Config) (Fetcher, error)

// // RegisterFetcher register fetcher
// func RegisterFetcher(name string, fetcher FetcherF) {
// 	injector.Register(name, fetcher)
// }

// // NewIndexer .
// func NewIndexer(config config.Config) (Indexer, error) {

// 	fetcherName := config.Get("fetcher").String("")

// 	if fetcherName == "" {
// 		return nil, xerrors.Wrapf(ErrParam, "fetcher name expect")
// 	}

// 	var f FetcherF
// 	if !injector.Get(fetcherName, &f) {
// 		return nil, xerrors.Wrapf(ErrParam, "unknown fetcher %s", fetcherName)
// 	}

// 	fetcher, err := f(config)

// 	if err != nil {
// 		return nil, xerrors.Wrapf(err, "create fetcher %s error", fetcherName)
// 	}

// 	return newIndexer(config, fetcher)
// }
