package bnb

import (
	"encoding/hex"

	"github.com/openzknetwork/gochain/rpc/bnb"

	"github.com/dynamicgo/xerrors"

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
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "ont provider can only handle tx.OntTxRequest")
	}
	if bnbTxRequest.GasPrice < gasPrice {
		bnbTxRequest.GasPrice = gasPrice
	}
	if bnbTxRequest.GasLimits < gasLimits {
		bnbTxRequest.GasLimits = gasLimits
	}
	sender, err := bnb.NewPrivateKeyManager(hex.EncodeToString(key.PriKey()))
	if err != nil {
		return nil, "", err
	}
	transfers := []bnb.Transfer{bnb.Transfer{ToAddr: bnb.AccAddress(bnbTxRequest.To), Coins: []bnb.Coin{bnb.Coin{Denom: "BNB", Amount: 500000000}}}}
	fromAddr := key.Address()
	fromCoins := bnb.Coins{}
	for _, t := range transfers {
		t.Coins = t.Coins.Sort()
		fromCoins = fromCoins.Plus(t.Coins)
	}
	sendMsg := bnb.CreateSendMsg(bnb.AccAddress(fromAddr), fromCoins, transfers)
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
	hexTx, err := sender.Sign(*signMsg)
	if err != nil {
		return nil, "", err
	}
	return hexTx, "", nil
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
