package tx

import (
	"errors"
	"math/big"

	"github.com/openzknetwork/gochain/rpc/ont"

	"github.com/dynamicgo/fixed"
	"github.com/openzknetwork/key"

	"github.com/dynamicgo/injector"
	"github.com/dynamicgo/xerrors"
)

var prefix = "LPT_GOCHAIN_"

// Errors
var (
	ErrProvider      = errors.New("unknown provider")
	ErrAddress       = errors.New("invalid address")
	ErrProperty      = errors.New("invalid property value")
	ErrInvalidRequst = errors.New("provider can't handle request")
)

// EthTxRequest .
type EthTxRequest struct {
	Nonce     uint64
	To        string
	GasPrice  *fixed.Number
	GasLimits *big.Int
	Value     *fixed.Number
	Script    []byte
}

// OntTxRequest .
type OntTxRequest struct {
	From      *ont.Account
	To        ont.Address
	GasPrice  uint64
	GasLimits uint64
	Value     uint64
}

// Property .
type Property map[string]interface{}

// Provider .
type Provider interface {
	Name() string                                                                               // provider offical name
	RawTransaction(key key.Key, request interface{}, property Property) ([]byte, string, error) // transfer global asset
}

// RegisterProvider register provider
func RegisterProvider(provider Provider) {
	injector.Register(prefix+provider.Name(), provider)
}

// RawTransaction .
func RawTransaction(providerName string, key key.Key, request interface{}, property Property) ([]byte, string, error) {
	var provider Provider
	if !injector.Get(prefix+providerName, &provider) {
		return nil, "", xerrors.Wrapf(ErrProvider, "unknown provider %s", providerName)
	}

	if property == nil {
		property = Property{}
	}

	return provider.RawTransaction(key, request, property)
}
