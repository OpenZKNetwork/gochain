package ont

import (
	"fmt"
	"math/rand"
)

type NativeContract struct {
	ontSdk *SDK
	Ont    *Ont
	// GlobalParams *GlobalParam
}

func newNativeContract(ontSdk *SDK) *NativeContract {
	native := &NativeContract{ontSdk: ontSdk}
	native.Ont = &Ont{native: native, ontSdk: ontSdk}
	// native.OntId = &OntId{native: native, ontSdk: ontSdk}
	// native.GlobalParams = &GlobalParam{native: native, ontSdk: ontSdk}
	return native
}

func (this *NativeContract) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress Address,
	method string,
	params []interface{},
) (*MutableTransaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := BuildNativeInvokeCode(contractAddress, version, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return this.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func (this *NativeContract) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	version byte,
	contractAddress Address,
	method string,
	params []interface{},
) (Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *NativeContract) PreExecInvokeNativeContract(
	contractAddress Address,
	version byte,
	method string,
	params []interface{},
) (*PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}

type Ont struct {
	ontSdk *SDK
	native *NativeContract
}

func (this *Ont) Symbol() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) BalanceOf(address Address) (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		BALANCEOF_NAME,
		[]interface{}{address[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ont) Name() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		NAME_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) Decimals() (byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return byte(decimals.Uint64()), nil
}

func (this *Ont) TotalSupply() (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

//NewInvokeTransaction return smart contract invoke transaction
func (this *SDK) NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *MutableTransaction {
	invokePayload := &InvokeCode{
		Code: invokeCode,
	}
	tx := &MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]Sig, 0, 0),
	}
	return tx
}

func (this *SDK) SignToTransaction(tx *MutableTransaction, signer Signer) error {
	if tx.Payer == ADDRESS_EMPTY {
		account, ok := signer.(*Account)
		if ok {
			tx.Payer = account.Address
		}
	}
	for _, sigs := range tx.Sigs {
		if PubKeysEqual([]PublicKey{signer.GetPublicKey()}, sigs.PubKeys) {
			//have already signed
			return nil
		}
	}
	txHash := tx.Hash()
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	if tx.Sigs == nil {
		tx.Sigs = make([]Sig, 0)
	}
	tx.Sigs = append(tx.Sigs, Sig{
		PubKeys: []PublicKey{signer.GetPublicKey()},
		M:       1,
		SigData: [][]byte{sigData},
	})
	return nil
}

// func (this *Ont) NewTransferTransaction(gasPrice, gasLimit uint64, from, to Address, amount uint64) (*MutableTransaction, error) {
// 	state := &State{
// 		From:  from,
// 		To:    to,
// 		Value: amount,
// 	}
// 	return this.NewMultiTransferTransaction(gasPrice, gasLimit, []*State{state})
// }

// func (this *Ont) Transfer(gasPrice, gasLimit uint64, from *Account, to Address, amount uint64) (Uint256, error) {
// 	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	err = this.ontSdk.SignToTransaction(tx, from)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	return this.ontSdk.SendTransaction(tx)
// }

// func (this *Ont) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*State) (*MutableTransaction, error) {
// 	return this.native.NewNativeInvokeTransaction(
// 		gasPrice,
// 		gasLimit,
// 		ONT_CONTRACT_VERSION,
// 		ONT_CONTRACT_ADDRESS,
// 		ont.TRANSFER_NAME,
// 		[]interface{}{states})
// }

// func (this *Ont) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (Uint256, error) {
// 	tx, err := this.NewMultiTransferTransaction(gasPrice, gasLimit, states)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	err = this.ontSdk.SignToTransaction(tx, signer)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	return this.ontSdk.SendTransaction(tx)
// }

// func (this *Ont) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to Address, amount uint64) (*types.MutableTransaction, error) {
// 	state := &ont.TransferFrom{
// 		Sender: sender,
// 		From:   from,
// 		To:     to,
// 		Value:  amount,
// 	}
// 	return this.native.NewNativeInvokeTransaction(
// 		gasPrice,
// 		gasLimit,
// 		ONT_CONTRACT_VERSION,
// 		ONT_CONTRACT_ADDRESS,
// 		ont.TRANSFERFROM_NAME,
// 		[]interface{}{state},
// 	)
// }

// func (this *Ont) TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to Address, amount uint64) (Uint256, error) {
// 	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	err = this.ontSdk.SignToTransaction(tx, sender)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	return this.ontSdk.SendTransaction(tx)
// }

// func (this *Ont) NewApproveTransaction(gasPrice, gasLimit uint64, from, to Address, amount uint64) (*types.MutableTransaction, error) {
// 	state := &ont.State{
// 		From:  from,
// 		To:    to,
// 		Value: amount,
// 	}
// 	return this.native.NewNativeInvokeTransaction(
// 		gasPrice,
// 		gasLimit,
// 		ONT_CONTRACT_VERSION,
// 		ONT_CONTRACT_ADDRESS,
// 		ont.APPROVE_NAME,
// 		[]interface{}{state},
// 	)
// }

// func (this *Ont) Approve(gasPrice, gasLimit uint64, from *Account, to Address, amount uint64) (Uint256, error) {
// 	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	err = this.ontSdk.SignToTransaction(tx, from)
// 	if err != nil {
// 		return UINT256_EMPTY, err
// 	}
// 	return this.ontSdk.SendTransaction(tx)
// }

// func (this *Ont) Allowance(from, to Address) (uint64, error) {
// 	type allowanceStruct struct {
// 		From Address
// 		To   Address
// 	}
// 	preResult, err := this.native.PreExecInvokeNativeContract(
// 		ONT_CONTRACT_ADDRESS,
// 		ONT_CONTRACT_VERSION,
// 		ont.ALLOWANCE_NAME,
// 		[]interface{}{&allowanceStruct{From: from, To: to}},
// 	)
// 	if err != nil {
// 		return 0, err
// 	}
// 	balance, err := preResult.Result.ToInteger()
// 	if err != nil {
// 		return 0, err
// 	}
// 	return balance.Uint64(), nil
// }
