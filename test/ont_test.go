package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/openzknetwork/gochain/tx"
	_ "github.com/openzknetwork/gochain/tx/provider"
	_ "github.com/openzknetwork/key/encryptor"
	"github.com/openzknetwork/key"
	_ "github.com/openzknetwork/key/provider"

	"github.com/dynamicgo/fixed"
	"github.com/openzknetwork/gochain/rpc/ont"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/signature"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
)

var account1 = "APTH9LF6gjXrbaDaWafajjAATS5nRa4dLc"
var account2 = "AHCxGDGUixcFzCJx749oerZUMK8t9XAZz8"

var pri1 = "12020b5d28dd09cff2f0b70549cee2b6a5a17cb9ce200fa66ca729c1c73ffa1adabf02c8b472dcee5ea6c7f205b5e152f6b4db743ad41fb9934755ec1a668a047f0f5f"
var pri2 = "120288feb8e91d6e9f0a47bd5de40e67bdd60688cde958fcdcdc584aaabcb5689a0502c2b845335dcf930bfb3d66f5b292f84cca6a33d73832a30e43b8c5bc01410962"

func TestNewAccount(t *testing.T) {
	password := []byte("123456")
	// wd, _ := os.Getwd()
	// walletFile := filepath.FromSlash(path.Join(wd, "wallet1.dat"))
	wallet := sdk.NewWallet("./wallet1.dat")
	acct, err := wallet.NewDefaultSettingAccount(password)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(acct.Address.ToBase58())
	}

	acc, err := wallet.GetAccountByAddress(account1, password)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(acc.Address.ToBase58())
	}

}

func TestOpenWallet(t *testing.T) {
	// password := []byte("123456")
	// wd, _ := os.Getwd()
	// walletFile := filepath.FromSlash(path.Join(wd, "wallet1.dat"))
	wallet, err := sdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(wallet.GetAccountCount())
	}
}

func TestContractAddress(t *testing.T) {
	// fmt.Println(ont.ONT_CONTRACT_ADDRESS.ToHexString())
}

func TestTransaction(t *testing.T) {
	const (
		// ECDSA curve label
		P224 byte = 1
		P256 byte = 2
		P384 byte = 3
		P521 byte = 4

		// SM2 curve label
		SM2P256V1 byte = 20

		// ED25519 curve label
		ED25519 byte = 25
	)
	// p1, _ := hex.DecodeString(pri1)
	// p2, _ := ont.HexToBytes(pri2)
	// ac1, err := ont.NewAccountFromPrivateKey(p1, ont.SHA256withECDSA)
	// if err != nil {
	// 	fmt.Printf("err1 %s \n", err.Error())
	// 	return
	// }
	// ac2, err := ont.NewAccountFromPrivateKey(p2, ont.SHA256withECDSA)
	// if err != nil {
	// 	fmt.Printf("err2 %s \n", err.Error())
	// 	return
	// }

	// client := ont.New("http://polaris1.ont.io:20336")

	// data, _, err := tx.RawTransaction("ont", ac1, &tx.OntTxRequest{
	// 	// From:      ac1,
	// 	To:        ac2.Address.ToBase58(),
	// 	GasPrice:  1000,
	// 	GasLimits: 500,
	// 	Value:     1,
	// }, nil)

	// if err != nil {
	// 	panic(err)
	// }
	// tx, err := client.SendRawTransaction(data)

	// if err != nil {
	// 	panic(err)
	// }
	// println(tx)
	// // tx, _ := testOntSdk.Native.Ont.NewTransferTransaction(500, 10000, add, add2, 1)

	// // testOntSdk.SignToTransaction(tx, account)
	// // tx2, _ := tx.IntoImmutable()

	// // var buffer bytes.Buffer
	// // tx2.Serialize(&buffer)
	// // txData := hex.EncodeToString(buffer.Bytes())
	// // tx3, _ := testOntSdk.GetMutableTx(txData)
	// // assert.Equal(t, tx, tx3)
	// // fmt.Printf("t %+v \n tx %+v \n tx3 %+v \n", t, tx, tx3)

	// // 75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb9cf
	// s, _ := common.AddressFromBase58(account1)
	// fmt.Printf("%s \n", s.ToHexString())
}

func TestDecimals(t *testing.T) {
	client := ont.New("http://polaris1.ont.io:20336")

	decimals, _ := client.Decimals()
	fmt.Printf("%d \n", decimals)
	ff, _ := fixed.New(int64(10000000), 9).Float().Float32()
	gasPrice := strconv.FormatFloat(float64(ff), 'f', 10, 32)
	fmt.Printf("%s \n", gasPrice)

}

func TestPri(t *testing.T) {
	// s,_:=ont.AddressFromHexString("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	// fmt.Println(s)
	ss, _ := ont.AddressFromHexString("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	// base58  AFmseVrdL9f9oyCzZefL9tG6UbvhPbdYzM

	b, _ := ont.AddressFromBase58("AFmseVrdL9f9oyCzZefL9tG6UbvhPbdYzM")
	h2b, _ := ont.HexToBytes("AFmseVrdL9f9oyCzZefL9tG6UbvhPbdYzM")
	fmt.Println(ss.ToBase58(), b.ToHexString(), ont.ToHexString(h2b), ss.ToHexString())
}

func TestSdkTransaction(t *testing.T) {
	testPasswd := []byte("123456")
	testOntSdk := sdk.NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	var wallet *sdk.Wallet
	var err error
	if !FileExisted("./wallet.dat") {
		wallet, err = testOntSdk.CreateWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	} else {
		wallet, err = testOntSdk.OpenWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	}

	a2, err := wallet.GetAccountByIndex(2, testPasswd)
	if err != nil {
		fmt.Println("")
		return
	}

	k, err := key.New("ont")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
	if err != nil {
		fmt.Printf("decrypt err %s", err.Error())
		return
	}
	println("address ", k.Address())
	p := ec.ConstructPrivateKey(k.PriKey(), k.Provider().Curve())
	privaKey := &ont.ECPrivateKey{
		Algorithm:  ont.ECDSA,
		PrivateKey: p,
	}

	from, err := common.AddressFromBase58(k.Address())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pub := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &p.PublicKey,
	}
	signer := &sdk.Account{
		PrivateKey: privaKey,
		PublicKey:  pub,
		Address:    from,
		SigScheme:  signature.SHA3_256withECDSA,
	}

	res, _ := testOntSdk.Native.Ont.Transfer(500, 20000, signer, a2.Address, 1)
	if err != nil {
		fmt.Printf("err %s \n", err.Error())
		return
	}

	fmt.Printf("res %s \n", res.ToHexString())
}

func FileExisted(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func TestKey(t *testing.T) {
	k, err := key.New("ont")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// var buff bytes.Buffer
	// err = key.Encrypt("wif", k, nil, &buff)

	// fmt.Printf("prikey %s \n address %s \n wif %s \n buff %+v \n", ont.ToHexString(k.PriKey()), k.Address(),buff.String(),buff)

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))

	client := ont.New("http://polaris1.ont.io:20336")
	println("from ", k.Address())
	data, _, err := tx.RawTransaction("ont", k, &tx.OntTxRequest{
		To:        "ASknPJZK6QVjkPB6or6X6WDF422az98LCs",
		GasPrice:  1000,
		GasLimits: 500,
		Value:     1,
	}, nil)

	if err != nil {
		fmt.Printf("RawTransaction error %s \n", err.Error())
		return
	}

	// r, err := ont.ParseNativeTxPayload(data)
	// if err != nil {
	// 	fmt.Printf("ParseNativeTxPayload error %s \n", err.Error())
	// 	return
	// }
	// fmt.Printf("r %+v \n", r)
	tx, err := client.SendRawTransaction(data)

	if err != nil {
		fmt.Printf("SendRawTransaction error %s \n", err.Error())
		return
	}
	println(tx)
}

func TestMKKey(t *testing.T) {
	k, err := key.New("ont")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// ont.NewAccountFromPrivateKey()
	fmt.Printf("key %+v \n  address %s \n pri %s \n pub %s \n", k, k.Address(), hex.EncodeToString(k.PriKey()), hex.EncodeToString(k.PubKey()))
}

func TestLocalTransaction(t *testing.T) {
	// testPasswd := []byte("123456")
	// testOntSdk := sdk.NewOntologySdk()
	// testOntSdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	// var wallet *sdk.Wallet
	// var err error
	// if !FileExisted("./wallet.dat") {
	// 	wallet, err = testOntSdk.CreateWallet("./wallet.dat")
	// 	if err != nil {
	// 		fmt.Println("[CreateWallet] error:", err)
	// 		return
	// 	}
	// } else {
	// 	wallet, err = testOntSdk.OpenWallet("./wallet.dat")
	// 	if err != nil {
	// 		fmt.Println("[CreateWallet] error:", err)
	// 		return
	// 	}
	// }
	// a2, err := wallet.GetAccountByIndex(2, testPasswd)
	// if err != nil {
	// 	fmt.Println("")
	// 	return
	// }

	k, err := key.New("ont")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	println("address ", k.Address())

	client := ont.New("http://polaris1.ont.io:20336")
	data, _, err := tx.RawTransaction("ont", k, &tx.OntTxRequest{
		To:        "ASknPJZK6QVjkPB6or6X6WDF422az98LCs",
		GasPrice:  1000,
		GasLimits: 500,
		Value:     1,
	}, nil)

	if err != nil {
		fmt.Printf("RawTransaction error %s \n", err.Error())
		return
	}
	res, err := client.SendRawTransaction(data)
	if err != nil {
		fmt.Printf("SendRawTransaction error %s \n", err.Error())
		return
	}

	fmt.Printf("res %s \n", res)
}

func TestTransfer(t *testing.T) {

	k, err := key.New("ont")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
	println("address ", k.Address())

	client := ont.New("http://polaris1.ont.io:20336")
	println("from ", k.Address())
	p := ec.ConstructPrivateKey(k.PriKey(), k.Provider().Curve())
	privaKey := &ont.ECPrivateKey{
		Algorithm:  ont.ECDSA,
		PrivateKey: p,
	}

	from, err := ont.AddressFromBase58(k.Address())
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	to, err := ont.AddressFromBase58("ASknPJZK6QVjkPB6or6X6WDF422az98LCs")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pub := &ont.ECPublicKey{
		Algorithm: ont.ECDSA,
		PublicKey: &p.PublicKey,
	}
	signer := &ont.Account{
		PrivateKey: privaKey,
		PublicKey:  pub,
		Address:    from,
		SigScheme:  ont.SHA3_256withECDSA,
	}
	// res, err := client.SendRawTransaction(data)
	res, err := client.Transfer(10000, 500, signer, to, 1)
	if err != nil {
		fmt.Printf("SendRawTransaction error %s \n", err.Error())
		return
	}

	fmt.Printf("res %s \n", res)
}
