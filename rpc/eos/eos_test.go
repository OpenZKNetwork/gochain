package eos

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

var client = New("https://mainnet.eoscanada.com", WithDebug())

func TestAccountInfo(t *testing.T) {
	account, err := client.GetAccount("gochain12345")
	require.NoError(t, err)

	println(prettyString(account))
}

func prettyString(val interface{}) string {
	buff, _ := json.MarshalIndent(val, "", "\t")
	return string(buff)
}
