package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/ontio/ontology-go-sdk/oep4"
	"github.com/ontio/ontology/account"

	"github.com/openzknetwork/gochain/script/neo/script"

	"github.com/openzknetwork/gochain/tx"
	_ "github.com/openzknetwork/gochain/tx/provider"
	"github.com/openzknetwork/key"
	_ "github.com/openzknetwork/key/encryptor"
	_ "github.com/openzknetwork/key/provider"

	"github.com/dynamicgo/fixed"
	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/gochain/rpc/ont"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/cmd/utils"
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
	password := []byte("123456")
	// wd, _ := os.Getwd()
	// walletFile := filepath.FromSlash(path.Join(wd, "wallet1.dat"))
	wallet, err := sdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(wallet.GetAccountCount())
	}
	a2, err := wallet.GetAccountByIndex(1, password)
	if err != nil {
		fmt.Println("")
		return
	}
	println(hex.EncodeToString(keypair.SerializePrivateKey(a2.PrivateKey)))
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

func TestParseHash(t *testing.T) {
	add, _ := ont.AddressFromHexString(string(ont.AddressByteArrayReverse([]byte("0239dcf9b4a46f15c5f23f20d52fac916a0bac0d"))))
	println(add.ToBase58())
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

// func TestTransfer(t *testing.T) {

// 	k, err := key.New("ont")
// 	if err != nil {
// 		fmt.Println(err.Error())
// 		return
// 	}

// 	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
// 	println("address ", k.Address())

// 	client := ont.New("http://polaris1.ont.io:20336")
// 	println("from ", k.Address())
// 	p := ec.ConstructPrivateKey(k.PriKey(), k.Provider().Curve())
// 	privaKey := &ont.ECPrivateKey{
// 		Algorithm:  ont.ECDSA,
// 		PrivateKey: p,
// 	}

// 	from, err := ont.AddressFromBase58(k.Address())
// 	if err != nil {
// 		fmt.Println(err.Error())
// 		return
// 	}

// 	to, err := ont.AddressFromBase58("ASknPJZK6QVjkPB6or6X6WDF422az98LCs")
// 	if err != nil {
// 		fmt.Println(err.Error())
// 		return
// 	}
// 	pub := &ont.ECPublicKey{
// 		Algorithm: ont.ECDSA,
// 		PublicKey: &p.PublicKey,
// 	}
// 	signer := &ont.Account{
// 		PrivateKey: privaKey,
// 		PublicKey:  pub,
// 		Address:    from,
// 		SigScheme:  ont.SHA3_256withECDSA,
// 	}
// 	// res, err := client.SendRawTransaction(data)
// 	res, err := client.Transfer(10000, 500, signer, to, 1)
// 	if err != nil {
// 		fmt.Printf("SendRawTransaction error %s \n", err.Error())
// 		return
// 	}

// 	fmt.Printf("res %s \n", res)
// }

func TestScript(t *testing.T) {
	k, err := key.New("ont")
	if err != nil {
		fmt.Printf("key.New error %s \n", err.Error())
		return
	}

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	const (
		ONT_CONTRACT_ADDRESS = "0100000000000000000000000000000000000000"
		ONG_CONTRACT_ADDRESS = "0200000000000000000000000000000000000000"
		OWN_CONTRACT_ADDRESS = "c43ce1a45253cb68617c8b5d2d504084e2e9baac"
	)
	client := ont.New("http://polaris1.ont.io:20336")

	fromAddess, _ := ont.AddressFromBase58(k.Address())
	from := fromAddess.ToHexString()
	toAddess, _ := ont.AddressFromBase58("ASknPJZK6QVjkPB6or6X6WDF422az98LCs")
	to := toAddess.ToHexString()
	fmt.Printf("from hex %s   to hex %s \n", from, to)
	st, err := script.New(k.Address()).NewScript(ONG_CONTRACT_ADDRESS, from, to, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, 1)
	if err != nil {
		fmt.Printf("NewScript error %s \n", err.Error())
		return
	}

	data, _, err := tx.RawTransaction("ont", k, &tx.OntTxRequest{
		// To:        "ASknPJZK6QVjkPB6or6X6WDF422az98LCs",
		GasPrice:  1000,
		GasLimits: 500,
		// Value:     1,
		Script: st,
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

func TestOwnContract(t *testing.T) {
	k, err := key.New("ont")
	if err != nil {
		fmt.Printf("key.New error %s \n", err.Error())
		return
	}

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// println(hex.EncodeToString(k.PriKey()))
	// return
	const (
		ONT_CONTRACT_ADDRESS = "0100000000000000000000000000000000000000"
		ONG_CONTRACT_ADDRESS = "0200000000000000000000000000000000000000"
		OWN_CONTRACT_ADDRESS = "c43ce1a45253cb68617c8b5d2d504084e2e9baac"
	)
	client := ont.New("http://127.0.0.1:20336")
	println(k.Address())
	fromAddess, _ := ont.AddressFromBase58(k.Address())
	from := fromAddess.ToBase58()
	toAddess, _ := ont.AddressFromBase58("AHHXD39GRmhcjqaobEVQdadzqo6BbWfJQ2")
	to := toAddess.ToBase58()
	fmt.Printf("from hex %s   to hex %s \n", from, to)
	st, err := script.New(k.Address()).NewScript(OWN_CONTRACT_ADDRESS, from, to, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, 1)
	// st, err := NewScript(OWN_CONTRACT_ADDRESS, from, to, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, 1)

	if err != nil {
		fmt.Printf("NewScript error %s \n", err.Error())
		return
	}

	data, _, err := tx.RawTransaction("ont", k, &tx.OntTxRequest{
		GasPrice:  2000,
		GasLimits: 500,
		Script:    st,
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

func NewScript(contractAddress, from, to string, version byte, method string, amount uint64) ([]byte, error) {
	builder := script.New(from)
	contractAddr, err := ont.AddressFromHexString(contractAddress)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse contract address error")
	}
	fromAddr, err := ont.AddressFromHexString(from)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse from address error")
	}
	toAddr, err := ont.AddressFromHexString(to)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse to address error")
	}
	state := &ont.State{
		From:  fromAddr,
		To:    toAddr,
		Value: amount,
	}
	params := []interface{}{[]*ont.State{state}}
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	if len(params) == 0 {
		params = append(params, "")
	}
	if contractAddress != ont.ONT_CONTRACT_ADDRESS.ToHexString() && contractAddress != ont.ONG_CONTRACT_ADDRESS.ToHexString() {
		params = []interface{}{"transfer", []interface{}{fromAddr, toAddr, big.NewInt(int64(amount))}}
	}
	err = BuildNeoVMParam(builder, params)
	if err != nil {
		return nil, err
	}
	if contractAddress != ont.ONT_CONTRACT_ADDRESS.ToHexString() && contractAddress != ont.ONG_CONTRACT_ADDRESS.ToHexString() {
		return BuildNeoVMInvokeCode(builder, contractAddr)
	}
	builder.EmitPushBytes([]byte(method))
	builder.EmitPushBytes(contractAddr[:])
	builder.EmitPushInteger(new(big.Int).SetInt64(int64(version)))
	builder.Emit(script.SYSCALL, nil)
	builder.EmitPushBytes([]byte(NATIVE_INVOKE_NAME))

	return builder.Bytes()
}

func BuildNeoVMInvokeCode(builder *script.Script, smartContractAddress ont.Address) ([]byte, error) {
	b, err := builder.Bytes()
	if err != nil {
		return nil, err
	}
	args := append(b, script.APPCALL)
	args = append(args, smartContractAddress[:]...)
	return args, nil
}

var NATIVE_INVOKE_NAME = "Ontology.Native.Invoke"

//buildNeoVMParamInter build neovm invoke param code
func BuildNeoVMParam(builder *script.Script, smartContractParams []interface{}) error {
	//VM load params in reverse order
	for i := len(smartContractParams) - 1; i >= 0; i-- {
		switch v := smartContractParams[i].(type) {
		case bool:
			builder.EmitPushBool(v)
		case byte:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int64:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case ont.Fixed64:
			builder.EmitPushInteger(big.NewInt(int64(v.GetData())))
		case uint64:
			val := big.NewInt(0)
			builder.EmitPushInteger(val.SetUint64(uint64(v)))
		case string:
			builder.EmitPushBytes([]byte(v))
		case *big.Int:
			builder.EmitPushInteger(v)
		case []byte:
			builder.EmitPushBytes(v)
		case ont.Address:
			builder.EmitPushBytes(v[:])
		case ont.Uint256:
			builder.EmitPushBytes(v.ToArray())
		case []interface{}:
			err := BuildNeoVMParam(builder, v)
			if err != nil {
				return err
			}
			builder.EmitPushInteger(big.NewInt(int64(len(v))))
			builder.Emit(script.PACK, nil)
		default:
			object := reflect.ValueOf(v)
			kind := object.Kind().String()
			if kind == "ptr" {
				object = object.Elem()
				kind = object.Kind().String()
			}
			switch kind {
			case "slice":
				ps := make([]interface{}, 0)
				for i := 0; i < object.Len(); i++ {
					ps = append(ps, object.Index(i).Interface())
				}
				err := BuildNeoVMParam(builder, []interface{}{ps})
				if err != nil {
					return err
				}
			case "struct":
				builder.EmitPushInteger(big.NewInt(0))
				builder.Emit(script.NEWSTRUCT, nil)
				builder.Emit(script.TOALTSTACK, nil)
				for i := 0; i < object.NumField(); i++ {
					field := object.Field(i)
					builder.Emit(script.DUPFROMALTSTACK, nil)
					err := BuildNeoVMParam(builder, []interface{}{field.Interface()})
					if err != nil {
						return err
					}
					builder.Emit(script.APPEND, nil)
				}
				builder.Emit(script.FROMALTSTACK, nil)
			default:
				return fmt.Errorf("unsupported param:%s", v)
			}
		}
	}
	return nil
}

func TestHex(t *testing.T) {
	f, _ := hex.DecodeString("7472616e73666572")
	println(string(f))

	a, _ := ont.AddressFromHexString("0200000000000000000000000000000000000000")
	println(a.ToBase58())
	println()

	println(len("a94f00eb9e6a13890992b4db768d3a8acd4b6f0f"))
	add, _ := ont.AddressFromHexString(string(ont.AddressByteArrayReverse([]byte("c43ce1a45253cb68617c8b5d2d504084e2e9baac"))))
	println(add.ToBase58())

	n, err := strconv.ParseUint("0010a5d4e800", 16, 64)
	if err != nil {
		panic(err)
	}

	println(n)

	fn, _ := fixed.FromHex("0010a5d4e800", 8)
	ff, _ := fn.Float().Float64()
	fmt.Printf("%0.7f \n", ff)

}

func TestContract(t *testing.T) {
	testPasswd := []byte("123456")
	testOntSdk := sdk.NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
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

	a1, err := wallet.GetAccountByIndex(1, testPasswd)
	if err != nil {
		fmt.Println(err)
		return
	}
	a2, err := wallet.GetAccountByIndex(2, testPasswd)
	if err != nil {
		fmt.Println(err)
		return
	}

	contract, err := common.AddressFromHexString("c43ce1a45253cb68617c8b5d2d504084e2e9baac")
	if err != nil {
		fmt.Println(err)
		return
	}

	oep := oep4.NewOep4(contract, testOntSdk)
	name, err := oep.Name()
	if err != nil {
		fmt.Println(err)
		return
	}
	println(name)

	total, err := oep.TotalSupply()
	if err != nil {
		fmt.Println(err)
		return
	}

	println(total.Int64())

	balance, err := oep.BalanceOf(a2.Address)
	if err != nil {
		fmt.Println(err)
		return
	}

	println(balance.Int64())
	return 
	transferResult, err := oep.Transfer(a1, a2.Address, big.NewInt(100), 500, 20000)
	if err != nil {
		fmt.Println(err)
		return
	}
	println(transferResult.ToHexString())
	return

	sender := &account.Account{
		PrivateKey: a1.PrivateKey,
		PublicKey:  a1.PublicKey,
		Address:    a1.Address,
		SigScheme:  a1.SigScheme,
	}
	params := []interface{}{"transfer", []interface{}{a1.Address, a2, 1}}
	rs, err := utils.InvokeNeoVMContract(uint64(500), uint64(20000), sender, contract, params)

	if err != nil {
		fmt.Println(err)
		return
	}
	println(rs)
}

func TestAddress(t *testing.T) {
	a, err := ont.AddressFromHexString("a9749d10b4f250444b53c9221e668218045cff86")
	if err != nil {
		fmt.Println(err)
		return
	}
	println(a.ToBase58())
}
