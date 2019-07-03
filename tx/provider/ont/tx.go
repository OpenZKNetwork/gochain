package ont

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/rand"

	"github.com/dynamicgo/xerrors"
	"github.com/ontio/ontology-crypto/ec"

	rand2 "crypto/rand"

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

	to, err := ont.AddressFromBase58(ontTxRequest.To)
	if err != nil {
		return nil, "", xerrors.Wrapf(err, "parse to address error")
	}

	return Raw(ontTxRequest.GasPrice, ontTxRequest.GasLimits, key, to, ontTxRequest.Value)
}

//Raw .
func Raw(gasPrice, gasLimit uint64, key key.Key, to ont.Address, amount uint64) ([]byte, string, error) {
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

	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	params := []interface{}{[]*ont.State{state}}
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := ont.BuildNativeInvokeCode(ont.ONT_CONTRACT_ADDRESS, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, params)
	if err != nil {
		return nil, "", fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	invokePayload := &ont.InvokeCode{
		Code: invokeCode,
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

// //Raw .
// func Raw(gasPrice, gasLimit uint64, key key.Key, to ont.Address, amount uint64) ([]byte, string, error) {
// 	p := ec.ConstructPrivateKey(key.PriKey(), key.Provider().Curve())
// 	privaKey := &ont.ECPrivateKey{
// 		Algorithm:  ont.ECDSA,
// 		PrivateKey: p,
// 	}

// 	from, err := ont.AddressFromBase58(key.Address())
// 	if err != nil {
// 		return nil, "", xerrors.Wrapf(err, "parse from address error")
// 	}
// 	pub := &ec.PublicKey{
// 		Algorithm: ec.ECDSA,
// 		PublicKey: &p.PublicKey,
// 	}
// 	signer := &ont.Account{
// 		PrivateKey: privaKey,
// 		PublicKey:  pub,
// 		Address:    from,
// 		SigScheme:  ont.SHA3_256withECDSA,
// 	}

// 	state := &ont.State{
// 		From:  from,
// 		To:    to,
// 		Value: amount,
// 	}
// 	params := []interface{}{state}
// 	invokeCode, err := ont.BuildNativeInvokeCode(ont.ONT_CONTRACT_ADDRESS, ont.ONT_CONTRACT_VERSION, ont.TRANSFER_NAME, params)
// 	if err != nil {
// 		return nil, "", fmt.Errorf("BuildNativeInvokeCode error:%s", err)
// 	}
// 	invokePayload := &ont.InvokeCode{
// 		Code: invokeCode,
// 	}
// 	tx := &ont.MutableTransaction{
// 		GasPrice: gasPrice,
// 		GasLimit: gasLimit,
// 		TxType:   ont.Invoke,
// 		Nonce:    rand.Uint32(),
// 		Payload:  invokePayload,
// 		Sigs:     make([]ont.Sig, 0, 0),
// 	}

// 	txHash := tx.Hash()

// 	sigData, err := signer.Sign(txHash.ToArray())
// 	if err != nil {
// 		return nil, "", fmt.Errorf("sign error:%s", err)
// 	}

// 	if tx.Sigs == nil {
// 		tx.Sigs = make([]ont.Sig, 0)
// 	}
// 	tx.Sigs = append(tx.Sigs, ont.Sig{
// 		PubKeys: []ont.PublicKey{pub},
// 		M:       1,
// 		SigData: [][]byte{sigData},
// 	})

// 	mutTx, err := tx.IntoImmutable()
// 	if err != nil {
// 		return nil, "", err
// 	}

// 	var buffer bytes.Buffer
// 	if err := mutTx.Serialize(&buffer); err != nil {
// 		return nil, "", fmt.Errorf("serialize error:%s", err)
// 	}
// 	// txData := hex.EncodeToString(buffer.Bytes())
// 	// rawParams := []interface{}{txData}
// 	hash := mutTx.Hash()
// 	return buffer.Bytes(), hash.ToHexString(), nil
// }

func Signature(k key.Key, msg []byte, opt interface{}) (sig *ont.Signature, err error) {
	var res ont.Signature
	hasher := ont.GetHash(ont.SHA256withECDSA)
	if hasher == nil {
		err = errors.New("signing failed: unknown scheme")
		return
	}
	p := ont.ConstructPrivateKey(k.PriKey(), k.Provider().Curve())

	hasher.Write(msg)
	digest := hasher.Sum(nil)
	r, s, err0 := ecdsa.Sign(rand2.Reader, p, digest)
	if err0 != nil {
		err = err0
		return
	}
	res.Value = &ont.DSASignature{R: r, S: s, Curve: k.Provider().Curve()}
	sig = &res

	return
}

func Serialize(sig *ont.Signature) ([]byte, error) {
	var buf bytes.Buffer
	v := sig.Value.(*ont.DSASignature)
	if v == nil || v.R == nil || v.S == nil {
		return nil, errors.New("serializeDSA: invalid argument")
	}

	size := (v.Curve.Params().BitSize + 7) >> 3
	res := make([]byte, size*2)

	r := v.R.Bytes()
	s := v.S.Bytes()
	copy(res[size-len(r):], r)
	copy(res[size*2-len(s):], s)
	buf.Write(res)
	bufb := buf.Bytes()

	// Treat SHA256withECDSA as a special case, using the signature
	// data directly without the signature scheme.
	if sig.Scheme == ont.SHA256withECDSA && len(bufb) == 65 {
		res = res[1:]
	}

	return bufb, nil
}
func init() {
	tx.RegisterProvider(&txProvider{})
}
