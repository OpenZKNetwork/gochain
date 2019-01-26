package eth

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/dynamicgo/fixed"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/gochain/tx/internal/rlp"
	"github.com/openzknetwork/key"
	"github.com/openzknetwork/sha3"
)

var (
	transferGasLimits = big.NewInt(21000)
	contractGasLimits = big.NewInt(55818)
	defaultGasPrice   = fixed.New(20000000000, 18)
)

// Tx .
type Tx struct {
	AccountNonce uint64    `json:"nonce"    gencodec:"required"`
	Price        *big.Int  `json:"gasPrice" gencodec:"required"`
	GasLimit     *big.Int  `json:"gas"      gencodec:"required"`
	Recipient    *[20]byte `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int  `json:"value"    gencodec:"required"`
	Payload      []byte    `json:"input"    gencodec:"required"`
	V            *big.Int  `json:"v" gencodec:"required"`
	R            *big.Int  `json:"r" gencodec:"required"`
	S            *big.Int  `json:"s" gencodec:"required"`
}

// NewTx create new eth tx
func newTx(nonce uint64, to string, amount, gasPrice *fixed.Number, gasLimit *big.Int, data []byte) *Tx {

	var recpoint *[20]byte

	if to != "" {
		var recipient [20]byte

		to = strings.TrimPrefix(to, "0x")

		toBytes, _ := hex.DecodeString(to)

		copy(recipient[:], toBytes)

		recpoint = &recipient
	}

	tx := &Tx{
		AccountNonce: nonce,
		Recipient:    recpoint,
		Payload:      data,
		GasLimit:     gasLimit,
		Price:        gasPrice.ValueBigInteger(),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}

	if amount != nil {
		tx.Amount = amount.ValueBigInteger()
	}

	return tx
}

// Sign .
func (tx *Tx) Sign(key key.Key) (string, error) {
	hw := sha3.NewKeccak256()

	rlp.Encode(hw, []interface{}{
		tx.AccountNonce,
		tx.Price,
		tx.GasLimit,
		tx.Recipient,
		tx.Amount,
		tx.Payload,
	})

	var hash [32]byte

	hw.Sum(hash[:0])

	sig, err := key.Sign(hash[:])

	if err != nil {
		return "", err
	}

	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	tx.V = new(big.Int).SetBytes(sig[64:])

	return tx.Hash(), nil
}

// Encode .
func (tx *Tx) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(tx)
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// Hash get tx hash string
func (tx *Tx) Hash() string {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, tx)
	return "0x" + hex.EncodeToString(hw.Sum(nil))
}

type txProvider struct {
}

func (provider *txProvider) Name() string {
	return "eth"
}

func (provider *txProvider) RawTransaction(key key.Key, request interface{}, property tx.Property) ([]byte, string, error) {
	ethTxRequest, ok := request.(*tx.EthTxRequest)

	if !ok {
		return nil, "", xerrors.Wrapf(tx.ErrInvalidRequst, "eth provider can only handle tx.EthTxRequest")
	}

	if ethTxRequest.GasPrice == nil {
		ethTxRequest.GasPrice = defaultGasPrice
	}

	if ethTxRequest.GasLimits == nil {
		if ethTxRequest.Script == nil {
			ethTxRequest.GasLimits = transferGasLimits
		} else {
			ethTxRequest.GasLimits = contractGasLimits
		}
	}

	return provider.doCall(key, ethTxRequest.Nonce, ethTxRequest.To, ethTxRequest.GasPrice, ethTxRequest.GasLimits, ethTxRequest.Value, ethTxRequest.Script, property)
}

func (provider *txProvider) doCall(key key.Key, nonce uint64, to string, gasPrice *fixed.Number, gasLimits *big.Int, amount *fixed.Number, script []byte, property tx.Property) ([]byte, string, error) {

	if property == nil {
		property = make(map[string]interface{})
	}

	if !key.Provider().ValidAddress(to) {
		return nil, "", xerrors.Wrapf(tx.ErrAddress, "invalid transfer to address %s", to)
	}

	tx := newTx(nonce, to, amount, gasPrice, gasLimits, script)

	txid, err := tx.Sign(key)

	if err != nil {
		return nil, "", xerrors.Wrapf(err, "sign tx error")
	}

	rawtx, err := tx.Encode()

	if err != nil {
		return nil, "", xerrors.Wrapf(err, "encode tx error")
	}

	return rawtx, txid, nil
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
