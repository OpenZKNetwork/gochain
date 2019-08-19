package trx

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/gochain/rpc/trx"
	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
)

var (
	gasLimits = uint64(20000)
	gasPrice  = uint64(500)
)

type txProvider struct {
}

func (provider *txProvider) Name() string {
	return "trx"
}

func (provider *txProvider) RawTransaction(key key.Key, request interface{}, property tx.Property) ([]byte, string, error) {
	trxTxRequest, ok := request.(*tx.TrxTxRequest)
	if !ok {
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "trx provider can only handle tx.TrxTxRequest")
	}
	transaction := trxTxRequest.Transaction
	if transaction.RawData.Contract[0].Parameter.Value.OwnerAddress != strings.ToLower(trx.Address2Hex(key.Address())) {
		return nil, "", xerrors.Wrapf(tx.ErrProperty, "transaction own address is not this address")
	}

	txByte, err := hex.DecodeString(trxTxRequest.Transaction.TxID)
	if err != nil {
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "parse tranaction property's txID error")
	}

	signByte, err := key.Sign(txByte)
	if err != nil {
		return nil, "", err
	}
	transaction.Signature = []string{hex.EncodeToString(signByte)}

	resp, err := json.Marshal(transaction)
	if err != nil {
		return nil, "", err
	}
	return resp, transaction.TxID, nil

}

func init() {
	tx.RegisterProvider(&txProvider{})
}
