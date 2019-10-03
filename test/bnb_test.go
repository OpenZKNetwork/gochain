package test

import (
	"encoding/hex"
	"testing"

	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
	"github.com/stretchr/testify/require"

	"github.com/openzknetwork/gochain/rpc/bnb"
	_ "github.com/openzknetwork/gochain/tx/provider"
)

var (
	c    bnb.Client
	key1 bnb.KeyManager //tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss
	key2 bnb.KeyManager //tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew
)

const privkey1 = "e0964451603e6e0e85a67d7e1fff26579e5f05108886b8ef8a940e5f3b861f6d"
const privkey2 = "9dde022641040e10f7d5be812990f6cab241c981ae83f4643858a4e35246d0af"

func initD() {
	bnb.Network = bnb.TestNetwork

	k1, err := bnb.NewPrivateKeyManager(privkey1)
	if err != nil {
		panic(err)
	}

	key1 = k1

	k2, err := bnb.NewPrivateKeyManager(privkey2)
	if err != nil {
		panic(err)
	}
	
	key2 = k2

	c = bnb.New("testnet-dex.binance.org", "https://seed-pre-s3.binance.org", 0)
}

func TestTx(t *testing.T) {
	bnb.Network = bnb.TestNetwork
	k, err := key.New("bnb")
	require.Nil(t, err)
	hexk1, err := hex.DecodeString((privkey1))
	require.Nil(t, err)
	k.SetBytes(hexk1)
	println(k.Address())
	return
	k2, err := key.New("bnb")
	require.Nil(t, err)
	hexk2, err := hex.DecodeString((privkey2))
	require.Nil(t, err)
	k2.SetBytes(hexk2)

	acc, err := c.GetAccount(k.Address())
	require.Nil(t, err)

	// s, b, err := bnb.DecodeAndConvert(k2.Address())
	// require.Nil(t, err)
	// println(string(s))
	// println(bnb.AccAddress(b).String())

	// fmt.Printf("k2 address %+v \n", bnb.AccAddress([]byte(k2.Address())))
	// return
	

	bt, _, err := tx.RawTransaction("bnb", k, &tx.BnbTxRequest{
		To:          k2.Address(),
		GasPrice:    37500,
		GasLimits:   1,
		Value:       1,
		ChainID:     acc.ChainID,
		AccNumber:   acc.Number,
		AccSequence: acc.Sequence,
	}, nil)
	require.Nil(t, err)

	hash, err := c.SendRawTransaction(bt)
	require.Nil(t, err)

	t.Logf("hash %s ", hash)
}
