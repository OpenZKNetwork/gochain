package bnb

import (
	"encoding/hex"
	"fmt"

	// "github.com/openzknetwork/gochain/rpc/bnb"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/gochain/rpc/bnb"
	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
)

var (
	gasLimits = uint64(1)
	gasPrice  = uint64(37500)
)

type txProvider struct {
}

func (provider *txProvider) Name() string {
	return "bnb"
}

func (provider *txProvider) RawTransaction(key key.Key, request interface{}, property tx.Property) ([]byte, string, error) {
	bnbTxRequest, ok := request.(*tx.BnbTxRequest)
	if !ok {
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "bnb provider can only handle tx.BnbTxRequest")
	}
	if bnbTxRequest.GasPrice < gasPrice {
		bnbTxRequest.GasPrice = gasPrice
	}
	if bnbTxRequest.GasLimits < gasLimits {
		bnbTxRequest.GasLimits = gasLimits
	}
	if bnbTxRequest.Denom == "" {
		bnbTxRequest.Denom = "BNB"
	}
	if bnbTxRequest.Value < 0 {
		return nil, "", xerrors.Wrapf(tx.ErrProperty, "value must bigger than 0")
	}
	pk := key.PriKey()
	if pk == nil {
		return nil, "", fmt.Errorf(" Only PrivKeySecp256k1 key is supported ")
	}
	sender, err := bnb.NewPrivateKeyManager(hex.EncodeToString(pk))
	if err != nil {
		return nil, "", err
	}
	_, toBytes, err := bnb.DecodeAndConvert(bnbTxRequest.To)
	if err != nil {
		return nil, "", err
	}
	transfers := []bnb.Transfer{bnb.Transfer{ToAddr: bnb.AccAddress(toBytes), Coins: []bnb.Coin{bnb.Coin{Denom: bnbTxRequest.Denom, Amount: int64(bnbTxRequest.Value)}}}}
	fromCoins := bnb.Coins{}
	for _, t := range transfers {
		t.Coins = t.Coins.Sort()
		fromCoins = fromCoins.Plus(t.Coins)
	}
	sendMsg := bnb.CreateSendMsg(bnb.AccAddress(sender.GetAddr()), fromCoins, transfers)
	signMsg := &bnb.StdSignMsg{
		ChainID: bnbTxRequest.ChainID,
		Memo:    "",
		Msgs:    []bnb.Msg{sendMsg},
		Source:  bnb.Source,
	}

	signMsg.Sequence = bnbTxRequest.AccSequence
	signMsg.AccountNumber = bnbTxRequest.AccNumber

	for _, m := range signMsg.Msgs {
		if err := m.ValidateBasic(); err != nil {
			return nil, "", err
		}
	}

	// Hex encoded signed transaction, ready to be posted to BncChain API
	sigBytes, err := sender.Sign(*signMsg)
	if err != nil {
		return nil, "", err
	}
	return sigBytes, "", nil
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
