package bnb

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/binance-chain/go-sdk/keys"
	"github.com/binance-chain/go-sdk/types"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/binance-chain/go-sdk/types/tx"
	"github.com/stretchr/testify/assert"
)

var (
	c   Client
	key keys.KeyManager //tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss

	key2 keys.KeyManager //tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew
)

const privkey1 = "e0964451603e6e0e85a67d7e1fff26579e5f05108886b8ef8a940e5f3b861f6d"
const privkey2 = "9dde022641040e10f7d5be812990f6cab241c981ae83f4643858a4e35246d0af"

func init() {
	Network = TestNetwork

	k, err := keys.NewKeyStoreKeyManager("keystore.txt", "123456Z,")
	if err != nil {
		panic(err)
	}

	key = k

	k, err = keys.NewKeyStoreKeyManager("key2.txt", "123456,Z")
	if err != nil {
		panic(err)
	}

	key2 = k

	c = New("testnet-dex.binance.org", "https://seed-pre-s3.binance.org", 0)
}

func TestKey(t *testing.T) {
	// 35c445a835eaefa4d6d11bfd8165d60459664abf5e440547f0ef9908c8695507
	k, err := keys.NewKeyManager()
	assert.Nil(t, err)
	pr, err := k.ExportAsPrivateKey()
	assert.Nil(t, err)
	println(k.GetAddr().String())
	println(pr)
}

func TestGet(t *testing.T) {
	b, _, err := c.Get("/block", map[string]string{"height": "1"}, false)
	assert.Nil(t, err)
	var resp map[string]interface{}
	err = json.Unmarshal(b, &resp)
	assert.Nil(t, err)
	fmt.Printf("%+v \n", resp)
}
func TestAccount(t *testing.T) {
	b, err := c.GetAccount("tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss")
	assert.Nil(t, err)

	fmt.Printf("%#v \n", b)
}
func TestBalance(t *testing.T) {
	b, err := c.GetBalance("tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss", "bnb")
	assert.Nil(t, err)
	fmt.Printf("%#v \n", b)
}

func TestGetTokens(t *testing.T) {
	b, err := c.GetTokens()
	assert.Nil(t, err)
	fmt.Printf("%#v \n", b)
}

func TestTransfer(t *testing.T) {
	prikey, err := key.ExportAsPrivateKey()
	assert.Nil(t, err)
	k1, err := NewPrivateKeyManager(prikey)
	assert.Nil(t, err)

	// //tbnb19m3dzz8e7tyned06ewv4nxecjy8up78f3cx8me
	// k2, err := keys.NewPrivateKeyManager(privkey2)
	// assert.Nil(t, err)
	// k2j, err := k2.GetAddr().MarshalJSON()
	// assert.Nil(t, err)
	// k2a := AccAddress{}
	// err = k2a.Unmarshal(k2j)
	// assert.Nil(t, err)

	prikey2, err := key2.ExportAsPrivateKey()
	assert.Nil(t, err)
	k2, err := NewPrivateKeyManager(prikey2)
	assert.Nil(t, err)
	fmt.Printf("k2 address %+v \n",k2.GetAddr())
	return 
	res, err := c.Transfer(k1, []Transfer{Transfer{ToAddr: k2.GetAddr(), Coins: []Coin{Coin{Denom: "BNB", Amount: 500000000}}}})
	assert.Nil(t, err)
	fmt.Printf("%#v \n", res)
}

func TestEq(t *testing.T) {
	s1 := `c2010a4c2a2c87fa0a220a14c3312ff20320638fa7bea5262b5ef7632fcbd226120a0a03424e421080c2d72f12220a14b7b6a07c2f1f3b80e108bbc7252eb5c81200726b120a0a03424e421080c2d72f12700a26eb5ae9872102f5a43dd795f44ebf1bf42144bee43c8539464c9f764d07fb041478b316fe5de312407809740cac092998d80db39170b7e28969374b7297ffaba201bac7ddf35ca8dd5f8249b2acbf6f69d3813a8421e62c8b1d82c95c55d04fb28741414737edc47c18b38e2a20022002`
	s2 := `c601f0625dee0a4c2a2c87fa0a220a14c3312ff20320638fa7bea5262b5ef7632fcbd226120a0a03424e421080c2d72f12220a14b7b6a07c2f1f3b80e108bbc7252eb5c81200726b120a0a03424e421080c2d72f12700a26eb5ae9872102f5a43dd795f44ebf1bf42144bee43c8539464c9f764d07fb041478b316fe5de312407809740cac092998d80db39170b7e28969374b7297ffaba201bac7ddf35ca8dd5f8249b2acbf6f69d3813a8421e62c8b1d82c95c55d04fb28741414737edc47c18b38e2a20022002`
	println(s1 == s2)
}

func TestGetTx(t *testing.T) {
	tx := "C022C197C77E493F454042A69BE77923E361118EF8E20B21E0AFB230501B771F"
	resp, err := c.GetTransactionReceipt(tx)
	assert.Nil(t, err)

	fmt.Printf("%+v \n", resp)
}

func TestBlocks(t *testing.T) {
	// s1 := "tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss"
	// s2 := "tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew"
	block, _, err := c.Get("/block", map[string]string{"height": "29507929"}, true)
	assert.Nil(t, err)
	res := new(Blocks)
	// err = amino.UnmarshalJSON(block, res)
	err = json.Unmarshal(block, res)
	assert.Nil(t, err)
	codec := types.NewCodec()

	for _, v := range res.Txs {
		m := new(tx.StdTx)
		codec.UnmarshalBinaryLengthPrefixed(v, m)
		sendMsg, ok := m.Msgs[0].(msg.SendMsg)
		if !ok {
			continue
		}
		sender := sendMsg.Inputs[0].Address.String()
		recipt := sendMsg.Outputs[0].Address.String()
		denom := sendMsg.Outputs[0].Coins[0].Denom
		amount := sendMsg.Outputs[0].Coins[0].Amount
		fmt.Printf("hash %s \n \n", strings.ToUpper(hex.EncodeToString(v.Hash())))
		fmt.Printf("sender %s recipt %s denom %s admount %d \n", sender, recipt, strings.ToLower(denom), amount)

		// for _, msg := range m.GetMsgs() {
		// address := msg.GetInvolvedAddresses()
		// for _, addr := range address {
		// 	if addr.String() != "tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss" && addr.String() != "tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew" {
		// 		// fmt.Printf("m %+v \n hash %s \n \n", m, strings.ToUpper(hex.EncodeToString(v.Hash())))
		// 		// fmt.Printf("address %s \n tx %+v\n ", addr.String(), m)
		// 		continue
		// 	}
		// }
		// sender := msg.(SendMsg).Inputs[0].Address.String()
		// recipt := msg.(SendMsg).Outputs[0].Address.String()
		// denom := msg.(SendMsg).Outputs[0].Coins[0].Denom
		// amount := msg.(SendMsg).Outputs[0].Coins[0].Amount
		// if sender != s1 && recipt != s1 && sender != s2 && recipt != s2 {
		// 	continue
		// }
		// fmt.Printf("hash %s \n \n", strings.ToUpper(hex.EncodeToString(v.Hash())))
		// fmt.Printf("sender %s recipt %s denom %s admount %d \n", sender, recipt, strings.ToLower(denom), amount)
		// }

	}
}

func TestParseTx(t *testing.T) {
	s := "5AHwYl3uCmPObcBDChT8HRgLsHanfEhoVnQe513mShsLvhIsRkMxRDE4MEJCMDc2QTc3QzQ4Njg1Njc0MUVFNzVERTY0QTFCMEJCRS05NzYaC1pDQi1GMDBfQk5CIAIoAjBbOICU69wDQAEScQom61rphyECzz53MSMBsYlzB9ioRcXH6X7lwkaCtdsygQQnxml71DASQLoz2Gco6DcJX1QrMQSBwZNqKYyr411IGkeKbAhi0vHIcEF14JFDb5pRqnKtc9LeCBWG8kNTaa8h/vEmflQbFvsYt8YpIM8HGgRtZW1vIGQ="
	// b, err := base64.StdEncoding.DecodeString(s)
	// assert.Nil(t, err)
	// m := &StdTx{}
	// err := Cdc.UnmarshalBinaryLengthPrefixed([]byte(s), m)
	// assert.Nil(t, err)
	// fmt.Printf("%+v \n", m)

	codec := types.NewCodec()
	decodetx64, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		fmt.Println("error:", err)
	}

	txs := []string{
		string(decodetx64),
	}

	parsedTxs := make([]tx.StdTx, len(txs))
	for i := range txs {
		err := codec.UnmarshalBinaryLengthPrefixed([]byte(txs[i]), &parsedTxs[i])

		if err != nil {
			fmt.Println("Error - codec unmarshal")
		}
	}

	bz, err := json.Marshal(parsedTxs)

	if err != nil {
		fmt.Println("Error - json marshal")

	}
	println(string(bz))
}
