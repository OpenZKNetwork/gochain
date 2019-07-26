package test

import (
	"testing"

	"github.com/openzknetwork/gochain/rpc/bnb"
	_ "github.com/openzknetwork/gochain/tx/provider"
)

var (
	c    bnb.Client
	key1 bnb.KeyManager //tbnb1cvcjlusryp3clfa755nzkhhhvvhuh53xd7alss

	key2 bnb.KeyManager //tbnb1k7m2qlp0ruacpcggh0rj2t44eqfqquntn6k8ew
)

const privkey1 = "e0964451603e6e0e85a67d7e1fff26579e5f05108886b8ef8a940e5f3b861f6d"
const privkey2 = "35c445a835eaefa4d6d11bfd8165d60459664abf5e440547f0ef9908c8695507"

func init() {
	bnb.Network = bnb.TestNetwork

	k1, err := bnb.NewPrivateKeyManager(privkey1)
	if err != nil {
		panic(err)
	}

	key1 = k1

	k2, err := bnb.NewPrivateKeyManager(privkey1)
	if err != nil {
		panic(err)
	}

	key2 = k2

	c = bnb.New("testnet-dex.binance.org", "https://seed-pre-s3.binance.org", 0)
}

func TestProvider(t *testing.T) {
	// eos.NewPrivateKeyManager()
}
