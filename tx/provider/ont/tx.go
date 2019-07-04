package ont

import (
	"fmt"
	"math/rand"

	"github.com/dynamicgo/xerrors"
	"github.com/ontio/ontology-crypto/ec"

	"github.com/openzknetwork/gochain/rpc/ont"
	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
)

var (
	gasLimits = uint64(20000)
	gasPrice  = uint64(500)
)

type txProvider struct {
}

func (provider *txProvider) Name() string {
	return "ont"
}

func (provider *txProvider) RawTransaction(key key.Key, request interface{}, property tx.Property) ([]byte, string, error) {
	ontTxRequest, ok := request.(*tx.OntTxRequest)
	if !ok {
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "ont provider can only handle tx.OntTxRequest")
	}
	if ontTxRequest.GasPrice < gasPrice {
		ontTxRequest.GasPrice = gasPrice
	}
	if ontTxRequest.GasLimits < gasLimits {
		ontTxRequest.GasLimits = gasLimits
	}

	// to, err := ont.AddressFromBase58(ontTxRequest.To)
	// if err != nil {
	// 	return nil, "", xerrors.Wrapf(err, "parse to address error")
	// }

	return Raw(ontTxRequest.GasPrice, ontTxRequest.GasLimits, key, ontTxRequest.Value, ontTxRequest.Script)
}

//Raw .
func Raw(gasPrice, gasLimit uint64, key key.Key, amount uint64, script []byte) ([]byte, string, error) {
	p := ec.ConstructPrivateKey(key.PriKey(), key.Provider().Curve())
	privaKey := &ont.ECPrivateKey{
		Algorithm:  ont.ECDSA,
		PrivateKey: p,
	}

	from, err := ont.AddressFromBase58(key.Address())
	if err != nil {
		return nil, "", xerrors.Wrapf(err, "parse from address error")
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

	// state := &ont.State{
	// 	From:  from,
	// 	To:    to,
	// 	Value: amount,
	// }
	// params := []interface{}{[]*ont.State{state}}
	// if params == nil {
	// 	params = make([]interface{}, 0, 1)
	// }
	// if len(params) == 0 {
	// 	params = append(params, "")
	// }
	// invokeCode, err := ont.BuildNativeInvokeCode(ont.ONT_CONTRACT_ADDRESS, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, params)
	// if err != nil {
	// 	return nil, "", fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	// }
	// invokePayload := &ont.InvokeCode{
	// 	Code: invokeCode,
	// }
	invokePayload := &ont.InvokeCode{
		Code: script,
	}
	tx := &ont.MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   ont.Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]ont.Sig, 0, 0),
	}
	if tx.Payer == ont.ADDRESS_EMPTY {
		tx.Payer = signer.Address
	}
	txHash := tx.Hash()

	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return nil, "", fmt.Errorf("sign error:%s", err)
	}

	if tx.Sigs == nil {
		tx.Sigs = make([]ont.Sig, 0)
	}
	tx.Sigs = append(tx.Sigs, ont.Sig{
		PubKeys: []ont.PublicKey{pub},
		M:       1,
		SigData: [][]byte{sigData},
	})

	mutTx, err := tx.IntoImmutable()
	if err != nil {
		return nil, "", err
	}

	// txData := hex.EncodeToString(buffer.Bytes())
	// rawParams := []interface{}{txData}
	hash := mutTx.Hash()

	return mutTx.ToArray(), hash.ToHexString(), nil
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
