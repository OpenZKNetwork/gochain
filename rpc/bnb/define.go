package bnb

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/types"
)

const (
	maxABCIPathLength     = 1024
	maxABCIDataLength     = 1024 * 1024
	maxTxLength           = 1024 * 1024
	maxABCIQueryStrLength = 1024
	maxTxSearchStrLength  = 1024
	maxUnConfirmedTxs     = 100

	tokenSymbolMaxLen = 14
	tokenSymbolMinLen = 3
)

const (
	DefaultApiSchema        = "https"
	DefaultWSSchema         = "wss"
	DefaultAPIVersionPrefix = "/api/v1"
	DefaultWSPrefix         = "/api/ws"
	NativeSymbol            = "BNB"

	GoSdkSource = 2
)

// Order routes
const (
	RouteNewOrder    = "orderNew"
	RouteCancelOrder = "orderCancel"
)

//CreateOrderResult .
type CreateOrderResult struct {
	TxCommitResult
	OrderID string
}

// SendTokenResult .
type SendTokenResult struct {
	TxCommitResult
}

// TxCommitResult for POST tx results
type TxCommitResult struct {
	Ok   bool   `json:"ok"`
	Log  string `json:"log"`
	Hash string `json:"hash"`
	Code int32  `json:"code"`
	Data string `json:"data"`
}

// ChainNetwork .
type ChainNetwork uint8

const (
	TestNetwork ChainNetwork = iota
	ProdNetwork
)

const (
	AddrLen = 20

	bech32PrefixConsPub  = "bcap"
	bech32PrefixConsAddr = "bca"
)

// Network .
var Network = ProdNetwork

// var Network = TestNetwork

//Bech32Prefixes .
func (this ChainNetwork) Bech32Prefixes() string {
	switch this {
	case TestNetwork:
		return "tbnb"
	case ProdNetwork:
		return "bnb"
	default:
		panic("Unknown network type")
	}
}

//Bech32ValidatorAddrPrefix .
func (this ChainNetwork) Bech32ValidatorAddrPrefix() string {
	return "bva"
}

//AccAddress .
type AccAddress []byte

// String representation
func (bz AccAddress) String() string {
	bech32Addr, err := ConvertAndEncode(Network.Bech32Prefixes(), bz.Bytes())
	if err != nil {
		panic(err)
	}
	return bech32Addr
}

func (bz AccAddress) Bytes() []byte {
	return bz
}

// Marshal needed for protobuf compatibility
func (bz AccAddress) Marshal() ([]byte, error) {
	return bz, nil
}

// Unmarshal needed for protobuf compatibility
func (bz *AccAddress) Unmarshal(data []byte) error {
	*bz = data
	return nil
}

// MarshalJSON to Marshals to JSON using Bech32
func (bz AccAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(bz.String())
}

// OrderSide /TimeInForce /OrderType are const, following FIX protocol convention
// Used as Enum
var OrderSide = struct {
	BUY  int8
	SELL int8
}{1, 2}

var sideNames = map[string]int8{
	"BUY":  1,
	"SELL": 2,
}

// IToSide conversion
func IToSide(side int8) string {
	switch side {
	case OrderSide.BUY:
		return "BUY"
	case OrderSide.SELL:
		return "SELL"
	default:
		return "UNKNOWN"
	}
}

// IToOrderType conversion
func IToOrderType(tpe int8) string {
	switch tpe {
	case OrderType.LIMIT:
		return "LIMIT"
	case OrderType.MARKET:
		return "MARKET"
	default:
		return "UNKNOWN"
	}
}

// IsValidOrderType validates that an order type is valid and supported by the matching engine
func IsValidOrderType(ot int8) bool {
	switch ot {
	case OrderType.LIMIT: // only allow LIMIT for now.
		return true
	default:
		return false
	}
}

// IsValidSide validates that a side is valid and supported by the matching engine
func IsValidSide(side int8) bool {
	switch side {
	case OrderSide.BUY, OrderSide.SELL:
		return true
	default:
		return false
	}
}

// IsValidTimeInForce validates that a tif code is correct
func IsValidTimeInForce(tif int8) bool {
	switch tif {
	case TimeInForce.GTC, TimeInForce.IOC:
		return true
	default:
		return false
	}
}

// CreateOrderMsg def
type CreateOrderMsg struct {
	Sender      AccAddress `json:"sender"`
	ID          string     `json:"id"`
	Symbol      string     `json:"symbol"`
	OrderType   int8       `json:"ordertype"`
	Side        int8       `json:"side"`
	Price       int64      `json:"price"`
	Quantity    int64      `json:"quantity"`
	TimeInForce int8       `json:"timeinforce"`
}

// Route is part of Msg interface
func (msg CreateOrderMsg) Route() string { return RouteNewOrder }

// Type is part of Msg interface
func (msg CreateOrderMsg) Type() string { return RouteNewOrder }

// GetSigners is part of Msg interface
func (msg CreateOrderMsg) GetSigners() []AccAddress { return []AccAddress{msg.Sender} }

// String is part of Msg interface
func (msg CreateOrderMsg) String() string {
	return fmt.Sprintf("CreateOrderMsg{Sender: %v, Id: %v, Symbol: %v, OrderSide: %v, Price: %v, Qty: %v}", msg.Sender, msg.ID, msg.Symbol, msg.Side, msg.Price, msg.Quantity)
}

// GetSignBytes - Get the bytes for the message signer to sign on
func (msg CreateOrderMsg) GetSignBytes() []byte {
	b, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return b
}

// GetInvolvedAddresses as part of the Msg interface
func (msg CreateOrderMsg) GetInvolvedAddresses() []AccAddress {
	return msg.GetSigners()
}

// ValidateBasic is used to quickly disqualify obviously invalid messages quickly
func (msg CreateOrderMsg) ValidateBasic() error {
	if len(msg.Sender) == 0 {
		return fmt.Errorf("ErrUnknownAddress %s", msg.Sender.String())
	}

	// `-` is required in the compound order id: <address>-<sequence>
	if len(msg.ID) == 0 || !strings.Contains(msg.ID, "-") {
		return fmt.Errorf("Invalid order ID:%s", msg.ID)
	}

	if msg.Quantity <= 0 {
		return fmt.Errorf("Invalid order Quantity, Zero/Negative Number:%d", msg.Quantity)
	}

	if msg.Price <= 0 {
		return fmt.Errorf("Invalid order Price, Zero/Negative Number:%d", msg.Price)
	}

	if !IsValidOrderType(msg.OrderType) {
		return fmt.Errorf("Invalid order type:%d", msg.OrderType)
	}

	if !IsValidSide(msg.Side) {
		return fmt.Errorf("Invalid side:%d", msg.Side)
	}

	if !IsValidTimeInForce(msg.TimeInForce) {
		return fmt.Errorf("Invalid TimeInForce:%d", msg.TimeInForce)
	}

	return nil
}

const (
	_      int8 = iota
	tifGTC int8 = iota
	_      int8 = iota
	tifIOC int8 = iota
)

// TimeInForce is an enum of TIF (Time in Force) options supported by the matching engine
var TimeInForce = struct {
	GTC int8
	IOC int8
}{tifGTC, tifIOC}

var timeInForceNames = map[string]int8{
	"GTC": tifGTC,
	"IOC": tifIOC,
}

const (
	_           int8 = iota
	orderMarket int8 = iota
	orderLimit  int8 = iota
)

// OrderType is an enum of order type options supported by the matching engine
var OrderType = struct {
	LIMIT  int8
	MARKET int8
}{orderLimit, orderMarket}

//Option .
type Option func(*StdSignMsg) *StdSignMsg

// StdSignMsg def
type StdSignMsg struct {
	ChainID       string `json:"chain_id"`
	AccountNumber int64  `json:"account_number"`
	Sequence      int64  `json:"sequence"`
	Msgs          []Msg  `json:"msgs"`
	Memo          string `json:"memo"`
	Source        int64  `json:"source"`
	Data          []byte `json:"data"`
}

// Bytes gets message bytes
func (msg StdSignMsg) Bytes() []byte {
	return StdSignBytes(msg.ChainID, msg.AccountNumber, msg.Sequence, msg.Msgs, msg.Memo, msg.Source, msg.Data)
}

// StdSignBytes returns the bytes to sign for a transaction.
func StdSignBytes(chainID string, accnum int64, sequence int64, msgs []Msg, memo string, source int64, data []byte) []byte {
	var msgsBytes []json.RawMessage
	for _, msg := range msgs {
		msgsBytes = append(msgsBytes, json.RawMessage(msg.GetSignBytes()))
	}

	bz, err := Cdc.MarshalJSON(StdSignDoc{
		AccountNumber: accnum,
		ChainID:       chainID,
		Memo:          memo,
		Msgs:          msgsBytes,
		Sequence:      sequence,
		Source:        source,
		Data:          data,
	})
	if err != nil {
		panic(err)
	}
	return MustSortJSON(bz)
}

// StdSignDoc def
type StdSignDoc struct {
	ChainID       string            `json:"chain_id"`
	AccountNumber int64             `json:"account_number"`
	Sequence      int64             `json:"sequence"`
	Memo          string            `json:"memo"`
	Source        int64             `json:"source"`
	Msgs          []json.RawMessage `json:"msgs"`
	Data          []byte            `json:"data"`
}

// Msg - Transactions messages must fulfill the Msg
type Msg interface {

	// Return the message type.
	// Must be alphanumeric or empty.
	Route() string

	// Returns a human-readable string for the message, intended for utilization
	// within tags
	Type() string

	// ValidateBasic does a simple validation check that
	// doesn't require access to any other information.
	ValidateBasic() error

	// Get the canonical byte representation of the Msg.
	GetSignBytes() []byte

	// Signers returns the addrs of signers that must sign.
	// CONTRACT: All signatures must be present to be valid.
	// CONTRACT: Returns addrs in some deterministic order.
	GetSigners() []AccAddress

	// Get involved addresses of this msg so that we can publish account balance change
	GetInvolvedAddresses() []AccAddress
}

// Source .
const Source int64 = 2

// Balance Account definition
type BalanceAccount struct {
	Number    int64          `json:"account_number"`
	Address   string         `json:"address"`
	Balances  []TokenBalance `json:"balances"`
	PublicKey []uint8        `json:"public_key"`
	Sequence  int64          `json:"sequence"`
}

type TokenBalance struct {
	Symbol string `json:"symbol"`
	Free   Fixed8 `json:"free"`
	Locked Fixed8 `json:"locked"`
	Frozen Fixed8 `json:"frozen"`
}

// Token definition
type Token struct {
	Name        string     `json:"name"`
	Symbol      string     `json:"symbol"`
	OrigSymbol  string     `json:"original_symbol"`
	TotalSupply Fixed8     `json:"total_supply"`
	Owner       AccAddress `json:"owner"`
	Mintable    bool       `json:"mintable"`
}

type ResultStatus struct {
	NodeInfo NodeInfo `json:"node_info"`
	SyncInfo SyncInfo `json:"sync_info"`

}
type NodeInfo struct {
	// Check compatibility.
	// Channels are HexBytes so easier to read as JSON
	Network string `json:"network"` // network/chain ID

}
type SyncInfo struct {
	Height uint32 `json:"latest_block_height"` // latest_block_height

}

// TxResponse .
type TxResponse struct {
	Hash   string `json:"hash"`
	Height string `json:"height"`
	Ok     bool   `json:"ok"`
	Tx     TxInfo `json:"tx"`
}

// TxInfo .
type TxInfo struct {
	Type  string  `json:"type"`
	Value TxValue `json:"value"`
}

// TxValue .
type TxValue struct {
	Source string  `json:"source"`
	Msg    []TxMsg `json:"msg"`
}

// TxMsg .
type TxMsg struct {
	Type  string     `json:"type"`
	Value TxMsgValue `json:"value"`
}

// TxMsgValue .
type TxMsgValue struct {
	Inputs  []TxMsgInput `json:"inputs"`
	Outputs []TxMsgInput `json:"outputs"`
}

// TxMsgInput Input
type TxMsgInput struct {
	Address string      `json:"address"`
	Coins   []TxMsgCoin `json:"coins"`
}

// TxMsgCoin .
type TxMsgCoin struct {
	Amount string `json:"amount"`
	Denom  string `json:"denom"`
}

// Input Input
type Input struct {
	Address AccAddress `json:"address"`
	Coins   Coins      `json:"coins"`
}

// MsgCdc .
var MsgCdc = amino.NewCodec()

// Return bytes to sign for Input
func (in Input) GetSignBytes() []byte {
	bin, err := MsgCdc.MarshalJSON(in)
	if err != nil {
		panic(err)
	}
	return MustSortJSON(bin)
}

// ValidateBasic - validate transaction input
func (in Input) ValidateBasic() error {
	if len(in.Address) == 0 {
		return fmt.Errorf("Len of input address is less than 1 ")
	}
	if !in.Coins.IsValid() {
		return fmt.Errorf("Inputs coins %v is invalid ", in.Coins)
	}
	if !in.Coins.IsPositive() {
		return fmt.Errorf("Inputs coins %v is negative ", in.Coins)
	}
	return nil
}

// Transaction Output
type Output struct {
	Address AccAddress `json:"address"`
	Coins   Coins      `json:"coins"`
}

// Return bytes to sign for Output
func (out Output) GetSignBytes() []byte {
	bin, err := MsgCdc.MarshalJSON(out)
	if err != nil {
		panic(err)
	}
	return MustSortJSON(bin)
}

// ValidateBasic - validate transaction output
func (out Output) ValidateBasic() error {
	if len(out.Address) == 0 {
		return fmt.Errorf("Len output %d should is less than 1 ", 0)
	}
	if !out.Coins.IsValid() {
		return fmt.Errorf("Coins is invalid ")
	}
	if !out.Coins.IsPositive() {
		return fmt.Errorf(" Coins is negative ")
	}
	return nil
}

// NewOutput - create a transaction output, used with SendMsg
func NewOutput(addr AccAddress, coins Coins) Output {
	output := Output{
		Address: addr,
		Coins:   coins,
	}
	return output
}

// SendMsg - high level transaction of the coin module
type SendMsg struct {
	Inputs  []Input  `json:"inputs"`
	Outputs []Output `json:"outputs"`
}

// NewMsgSend - construct arbitrary multi-in, multi-out send msg.
func NewMsgSend(in []Input, out []Output) SendMsg {
	return SendMsg{Inputs: in, Outputs: out}
}
func (msg SendMsg) Route() string { return "bank" } // TODO: "bank/send"
func (msg SendMsg) Type() string  { return "send" }

// Implements Msg.
func (msg SendMsg) ValidateBasic() error {
	if len(msg.Inputs) == 0 {
		return fmt.Errorf("Len of inputs is less than 1 ")
	}
	if len(msg.Outputs) == 0 {
		return fmt.Errorf("Len of outputs is less than 1 ")
	}
	// make sure all inputs and outputs are individually valid
	var totalIn, totalOut Coins
	for _, in := range msg.Inputs {
		if err := in.ValidateBasic(); err != nil {
			return err
		}
		totalIn = totalIn.Plus(in.Coins)
	}
	for _, out := range msg.Outputs {
		if err := out.ValidateBasic(); err != nil {
			return err
		}
		totalOut = totalOut.Plus(out.Coins)
	}
	// make sure inputs and outputs match
	if !totalIn.IsEqual(totalOut) {
		return fmt.Errorf("inputs %v and outputs %v don't match", totalIn, totalOut)
	}
	return nil
}

// Implements Msg.
func (msg SendMsg) GetSignBytes() []byte {
	b, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return b
}

// Implements Msg.
func (msg SendMsg) GetSigners() []AccAddress {
	addrs := make([]AccAddress, len(msg.Inputs))
	for i, in := range msg.Inputs {
		addrs[i] = in.Address
	}
	return addrs
}

func (msg SendMsg) GetInvolvedAddresses() []AccAddress {
	numOfInputs := len(msg.Inputs)
	numOfOutputs := len(msg.Outputs)
	addrs := make([]AccAddress, numOfInputs+numOfOutputs, numOfInputs+numOfOutputs)
	for i, in := range msg.Inputs {
		addrs[i] = in.Address
	}
	for i, out := range msg.Outputs {
		addrs[i+numOfInputs] = out.Address
	}
	return addrs
}

// Transfer .
type Transfer struct {
	ToAddr AccAddress
	Coins  Coins
}

// StdSignature Signature
type StdSignature struct {
	crypto.PubKey `json:"pub_key"` // optional
	Signature     []byte           `json:"signature"`
	AccountNumber int64            `json:"account_number"`
	Sequence      int64            `json:"sequence"`
}

// NewStdTx to instantiate an instance
func NewStdTx(msgs []Msg, sigs []StdSignature, memo string, source int64, data []byte) StdTx {
	return StdTx{
		Msgs:       msgs,
		Signatures: sigs,
		Memo:       memo,
		Source:     source,
		Data:       data,
	}
}

// StdTx def
type StdTx struct {
	Msgs       []Msg          `json:"msg"`
	Signatures []StdSignature `json:"signatures"`
	Memo       string         `json:"memo"`
	Source     int64          `json:"source"`
	Data       []byte         `json:"data"`
}

// GetMsgs def
func (tx StdTx) GetMsgs() []Msg { return tx.Msgs }

//Codec .
type Codec struct {
	mtx              sync.RWMutex
	sealed           bool
	typeInfos        map[reflect.Type]*TypeInfo
	interfaceInfos   []*TypeInfo
	concreteInfos    []*TypeInfo
	disfixToTypeInfo map[DisfixBytes]*TypeInfo
	nameToTypeInfo   map[string]*TypeInfo
}

// TypeInfo .
type TypeInfo struct {
	Type      reflect.Type // Interface type.
	PtrToType reflect.Type
	ZeroValue reflect.Value
	ZeroProto interface{}
	InterfaceInfo
	ConcreteInfo
	StructInfo
}

// Lengths
const (
	PrefixBytesLen = 4
	DisambBytesLen = 3
	DisfixBytesLen = PrefixBytesLen + DisambBytesLen
)

// Prefix types
type (
	PrefixBytes [PrefixBytesLen]byte
	DisambBytes [DisambBytesLen]byte
	DisfixBytes [DisfixBytesLen]byte // Disamb+Prefix
)

// InterfaceInfo .
type InterfaceInfo struct {
	Priority     []DisfixBytes               // Disfix priority.
	Implementers map[PrefixBytes][]*TypeInfo // Mutated over time.
	InterfaceOptions
}

// InterfaceOptions .
type InterfaceOptions struct {
	Priority           []string // Disamb priority.
	AlwaysDisambiguate bool     // If true, include disamb for all types.
}

// ConcreteInfo .
type ConcreteInfo struct {

	// These fields are only set when registered (as implementing an interface).
	Registered       bool // Registered with RegisterConcrete().
	PointerPreferred bool // Deserialize to pointer type if possible.
	// NilPreferred     bool        // Deserialize to nil for empty structs if PointerPreferred.
	Name            string      // Registered name.
	Disamb          DisambBytes // Disambiguation bytes derived from name.
	Prefix          PrefixBytes // Prefix bytes derived from name.
	ConcreteOptions             // Registration options.

	// These fields get set for all concrete types,
	// even those not manually registered (e.g. are never interface values).
	IsAminoMarshaler       bool         // Implements MarshalAmino() (<ReprObject>, error).
	AminoMarshalReprType   reflect.Type // <ReprType>
	IsAminoUnmarshaler     bool         // Implements UnmarshalAmino(<ReprObject>) (error).
	AminoUnmarshalReprType reflect.Type // <ReprType>
}

type ConcreteOptions struct {
}

type StructInfo struct {
	Fields []FieldInfo // If a struct.
}

type FieldInfo struct {
	Name         string        // Struct field name
	Type         reflect.Type  // Struct field type
	Index        int           // Struct field index
	ZeroValue    reflect.Value // Could be nil pointer unlike TypeInfo.ZeroValue.
	UnpackedList bool          // True iff this field should be encoded as an unpacked list.
	FieldOptions               // Encoding options
}

type FieldOptions struct {
	JSONName      string // (JSON) field name
	JSONOmitEmpty bool   // (JSON) omitempty
	BinFixed64    bool   // (Binary) Encode as fixed64
	BinFixed32    bool   // (Binary) Encode as fixed32
	BinFieldNum   uint32 // (Binary) max 1<<29-1

	Unsafe        bool // e.g. if this field is a float.
	WriteEmpty    bool // write empty structs and lists (default false except for pointers)
	EmptyElements bool // Slice and Array elements are never nil, decode 0x00 as empty struct.
}

// Blocks .
type Blocks struct {
	SResult `json:"result"`
}
type SResult struct {
	Block `json:"block"`
}

type Block struct {
	Data `json:"data"`
}

type Data struct {
	Txs []types.Tx `json:"txs"`
}

//Transaction .
type Transaction struct {
	GasPrice uint64
	GasLimit uint64
	From     string
	To       string
	Symbol   string
	Amount   int64
	Block    int64
	Tx       string
	T        time.Time
}
