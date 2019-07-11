package eth

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var client Client

func init() {
	client = New("https://ropsten.infura.io/OTFK50Z1PCljMOeEAlA9")
}

func TestGasPrice(t *testing.T) {
	price, err := client.SuggestGasPrice()

	assert.NoError(t, err)

	println(fmt.Sprintf("%d", price))

	decimals, err := client.DecimalsOfAsset("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2")
	assert.NoError(t, err)
	println(fmt.Sprintf("%d", decimals))
}

func TestHex(t *testing.T) {
	b, err := hex.DecodeString("7472616e73666572")
	assert.NoError(t, err)
	println(string(b))
}
