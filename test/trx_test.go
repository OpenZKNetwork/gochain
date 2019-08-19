package test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openzknetwork/gochain/rpc/trx"
	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
)

const (
	trxAddress = "TU16jgCKnsqbvvuGGwrZSDmP3h3hv6fqVx"
	trxPri     = "BED37B6E9F104D5E3730C1B5ACA24DEA1BFCF08EDE78B7CD5B961F1DD98B1EF1"
	trxTxID    = "37b4a05c49512a5752fa58049ec0d788909a57509e5f0d98631adedde1bc5489"
)

func TestTrxLocalTransaction(t *testing.T) {
	k, err := key.New("trx")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pri1 := "BED37B6E9F104D5E3730C1B5ACA24DEA1BFCF08EDE78B7CD5B961F1DD98B1EF1"
	p1, err := hex.DecodeString(pri1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	k.SetBytes(p1)

	println("address ", k.Address())

	client := trx.New("https://api.shasta.trongrid.io")
	to := "T9yai3UbXbDaGpVdsDHZyZC3wjqSLk4aor"
	amount := uint32(1)
	transaction, err := client.CreateTransaction(k.Address(), to, amount)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	data, _, err := tx.RawTransaction("trx", k, &tx.TrxTxRequest{
		To:          "T9yai3UbXbDaGpVdsDHZyZC3wjqSLk4aor",
		Value:       1,
		Transaction: *transaction,
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

func TestTrxGetAccount(t *testing.T) {
	client := getClient()
	account, err := client.GetAccount(trxAddress)
	require.Nil(t, err)
	print(account)
}

func TestTrxGetBalance(t *testing.T) {
	client := getClient()
	balance, err := client.GetBalance(trxAddress, "TRX")
	require.Nil(t, err)
	print(balance)
}

func TestTrxGetTransactionReceipt(t *testing.T) {
	client := getClient()
	recipt, err := client.GetTransactionReceipt(trxTxID)
	require.Nil(t, err)
	print(recipt)
}

func TestTrxGetTransactionFee(t *testing.T) {
	client := getClient()
	fee, err := client.GetTransactionFee(trxTxID)
	require.Nil(t, err)
	print(fee)
}

func TestTrxGetBlockByNumber(t *testing.T) {
	client := getClient()
	block, err := client.GetBlockByNumber(1635734)
	require.Nil(t, err)
	print(block)
}
func TestTrxBestBlockNumber(t *testing.T) {
	client := getClient()
	bestblock, err := client.BestBlockNumber()
	require.Nil(t, err)
	print(bestblock)
}
func getClient() trx.Client {
	return trx.New("https://api.shasta.trongrid.io")
}

func print(data interface{}) {
	fmt.Printf("%+v \n", data)
}
