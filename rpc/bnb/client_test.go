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

	key3 keys.KeyManager
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

	k, err = keys.NewKeyStoreKeyManager("key3.txt", "123456Z,")
	if err != nil {
		panic(err)
	}

	key3 = k

	client, err := New("testnet-dex.binance.org", "https://seed-pre-s3.binance.org", 0)
	if err != nil {
		panic(err)
	}
	c = client
}

func TestBestNumber(t *testing.T) {

	for i := 1; i < 10; i++ {
		num, err := c.BestBlockNumber()
		assert.Nil(t, err)
		fmt.Printf("%d \n", num)
		block, err := c.GetBlockByNumber(num)
		assert.Nil(t, err)

		fmt.Printf("%#v \n", block.BlockMeta)
	}

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
	b, _, err := c.Get("/block", map[string]string{"height": "1"}, true)
	assert.Nil(t, err)
	var resp map[string]interface{}
	err = json.Unmarshal(b, &resp)
	assert.Nil(t, err)
	fmt.Printf("%+v \n", resp)
}

func TestGetBlock(t *testing.T) {
	b, err := c.GetBlockByNumber(29507929)
	assert.Nil(t, err)

	fmt.Printf("%#v \n", b)

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
	fmt.Printf("k2 address %+v \n", k2.GetAddr())
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
	// tx := "C022C197C77E493F454042A69BE77923E361118EF8E20B21E0AFB230501B771F"
	tx := "906F29938F9D3B62CB1D84787ECF706D76579A04DD693754A73B8F7EB0F51B45"

	resp, err := c.GetTransactionReceipt(tx)
	assert.Nil(t, err)

	fmt.Printf("%+v \n", resp)
}

func TestBlocks(t *testing.T) {
	// s1 := "tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss"
	// s2 := "tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew"
	//transfer  41894952
	//data &tx.StdTx{Msgs:[]msg.Msg{msg.SendMsg{Inputs:[]msg.Input{msg.Input{Address:types.AccAddress{0xc3, 0x31, 0x2f, 0xf2, 0x3, 0x20, 0x63, 0x8f, 0xa7, 0xbe, 0xa5, 0x26, 0x2b, 0x5e, 0xf7, 0x63, 0x2f, 0xcb, 0xd2, 0x26}, Coins:types.Coins{types.Coin{Denom:"BNB", Amount:1000000000}}}}, Outputs:[]msg.Output{msg.Output{Address:types.AccAddress{0x53, 0xf2, 0xb7, 0xdc, 0x97, 0x63, 0x1, 0x56, 0x89, 0xd5, 0x4f, 0x3c, 0xcd, 0xec, 0xd0, 0x1a, 0xab, 0x50, 0xcd, 0x23}, Coins:types.Coins{types.Coin{Denom:"BNB", Amount:1000000000}}}}}}, Signatures:[]tx.StdSignature(nil), Memo:"", Source:0, Data:[]uint8(nil)}
	//dex 41848386
	//data &tx.StdTx{Msgs:[]msg.Msg{msg.CreateOrderMsg{Sender:types.AccAddress{0xc3, 0x31, 0x2f, 0xf2, 0x3, 0x20, 0x63, 0x8f, 0xa7, 0xbe, 0xa5, 0x26, 0x2b, 0x5e, 0xf7, 0x63, 0x2f, 0xcb, 0xd2, 0x26}, ID:"C3312FF20320638FA7BEA5262B5EF7632FCBD226-30", Symbol:"QRL-EAB_BNB", OrderType:1, Side:-1, Price:50000000, Quantity:200000000, TimeInForce:-1}}, Signatures:[]tx.StdSignature(nil), Memo:"", Source:0, Data:[]uint8(nil)}

	block, _, err := c.Get("/block", map[string]string{"height": "43576089"}, true)
	assert.Nil(t, err)
	res := new(Blocks)
	// err = amino.UnmarshalJSON(block, res)
	err = json.Unmarshal(block, res)
	assert.Nil(t, err)
	codec := types.NewCodec()

	for _, v := range res.Txs {
		m := new(tx.StdTx)
		codec.UnmarshalBinaryLengthPrefixed(v, m)
		fmt.Printf("data %#v \n", m)
		for k, _ := range m.Msgs {

			if sendMsg, ok := m.Msgs[k].(msg.SendMsg); ok {
				sender := sendMsg.Inputs[0].Address.String()
				recipt := sendMsg.Outputs[0].Address.String()
				denom := sendMsg.Outputs[0].Coins[0].Denom
				amount := sendMsg.Outputs[0].Coins[0].Amount
				fmt.Printf("hash %s \n \n", strings.ToUpper(hex.EncodeToString(v.Hash())))
				fmt.Printf("sender %s recipt %s denom %s amount %d \n", sender, recipt, strings.ToLower(denom), amount)
			}
			if sendMsg, ok := m.Msgs[k].(msg.CreateOrderMsg); ok {
				id:=sendMsg.ID
				sender:=sendMsg.Sender.String()
				symble:=sendMsg.Symbol
				// orderType:=sendMsg.OrderType
				side:=sendMsg.Side  //-1 buy
				price:=sendMsg.Price
				quantity:=sendMsg.Quantity
				fmt.Printf("id %s sender %s symble %s side %d price %d quantity %d \n",id, sender, symble, side, price,quantity)

			}
		}
		

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

func TestKey3(t *testing.T) {
	println(key3.GetAddr().String())
}
