package ont

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/dynamicgo/fixed"
	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/gochain/rpc/ont"
	"github.com/openzknetwork/gochain/tx"
	"github.com/openzknetwork/key"
)

var (
	transferGasLimits = big.NewInt(21000)
	contractGasLimits = big.NewInt(55818)
	defaultGasPrice   = fixed.New(20000000000, 18)
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

	return Raw(ontTxRequest.GasPrice, ontTxRequest.GasLimits, ontTxRequest.From, ontTxRequest.To, ontTxRequest.Value)
}

//Raw .
func Raw(gasPrice, gasLimit uint64, from *ont.Account, to ont.Address, amount uint64) ([]byte, string, error) {
	state := &ont.State{
		From:  from.Address,
		To:    to,
		Value: amount,
	}
	params := []interface{}{state}
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
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
		tx.Payer = from.Address
	}
	for _, sigs := range tx.Sigs {
		if !ont.PubKeysEqual([]ont.PublicKey{from.GetPublicKey()}, sigs.PubKeys) {
			//have already signed
			txHash := tx.Hash()
			sigData, err := from.Sign(txHash.ToArray())
			if err != nil {
				return nil, "", fmt.Errorf("sign error:%s", err)
			}
			if tx.Sigs == nil {
				tx.Sigs = make([]ont.Sig, 0)
			}
			tx.Sigs = append(tx.Sigs, ont.Sig{
				PubKeys: []ont.PublicKey{from.GetPublicKey()},
				M:       1,
				SigData: [][]byte{sigData},
			})
		}
	}

	mutTx, err := tx.IntoImmutable()
	if err != nil {
		return nil, "", err
	}

	var buffer bytes.Buffer
	if err := mutTx.Serialize(&buffer); err != nil {
		return nil, "", fmt.Errorf("serialize error:%s", err)
	}
	// txData := hex.EncodeToString(buffer.Bytes())
	// rawParams := []interface{}{txData}
	hash := mutTx.Hash()
	return buffer.Bytes(), hash.ToHexString(), nil
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
