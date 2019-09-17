package ont

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/openzknetwork/gochain/internal/base58"
)

const (
	//getVersion .
	getVersion = "getversion"
	//getTransaction .
	getTransaction = "getrawtransaction"
	//sendTransaction .
	sendTransaction = "sendrawtransaction"
	// getBlock .
	getBlock = "getblock"
	//getBlockCount .
	getBlockCount = "getblockcount"
	//getBlockHash .
	getBlockHash = "getblockhash"
	//getCurrentBlockHash .
	getCurrentBlockHash = "getbestblockhash"
	// getBalance .
	getBalance = "getbalance"
	//getSmartCodeEvent .
	getSmartCodeEvent = "getsmartcodeevent"
	//getstorage .
	getStorage = "getstorage"
	//getSmartContract .
	getSmartContract = "getcontractstate"
	//getGenerateBlockTime .
	getGenerateBlockTime = "getgenerateblocktime"
	//getMerkleProof .
	getMerkleProof = "getmerkleproof"
	//getNetworkID .
	getNetworkID = "getnetworkid"
	//getMemPoolTxCount .
	getMemPoolTxCount = "getmempooltxcount"
	//getMemPoolTxState
	getMemPoolTxState = "getmempooltxstate"
	//getBlockTxHashByHegiht
	getBlockTxHashByHegiht = "getblocktxsbyheight"
	//getBlockHeightByTxHash
	getBlockHeightByTxHash = "getblockheightbytxhash"
	//sendEmergencyGovReq
	sendEmergencyGovReq = "sendemergencygovreq"
	//getBlockRootWhitNewTxRoot
	getBlockRootWhitNewTxRoot = "getblockrootwithnewtxroot"

	//getGasprice
	getGasPrice = "getgasprice"
)

//JsonRpc version
const jsonRPCVersion = "2.0"

//JSONResponse object response for JsonRpcRequest
type JSONResponse struct {
	ID     string          `json:"id"`
	Error  int64           `json:"error"`
	Desc   string          `json:"desc"`
	Result json.RawMessage `json:"result"`
}

//JSONReqest object in rpc
type JSONReqest struct {
	Version string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

const (
	UNBOUND_TIME_OFFSET = "unboundTimeOffset"
	TOTAL_SUPPLY_NAME   = "totalSupply"
	INIT_NAME           = "init"
	TRANSFER_NAME       = "transfer"
	APPROVE_NAME        = "approve"
	TRANSFERFROM_NAME   = "transferFrom"
	NAME_NAME           = "name"
	SYMBOL_NAME         = "symbol"
	DECIMALS_NAME       = "decimals"
	TOTALSUPPLY_NAME    = "totalSupply"
	BALANCEOF_NAME      = "balanceOf"
	ALLOWANCE_NAME      = "allowance"
)

var one = new(big.Int).SetInt64(1)

type invertible interface {
	Inverse(*big.Int) *big.Int
}

const (
	aesIV = "IV for <SM2> CTR"

	// DEFAULT_ID is the default user id used in Sign and Verify
	DEFAULT_ID = "1234567812345678"
)

var zeroReader = &zr{}

type zr struct {
	io.Reader
}

var (
	ONT_CONTRACT_ADDRESS, _           = AddressFromHexString("0100000000000000000000000000000000000000")
	ONG_CONTRACT_ADDRESS, _           = AddressFromHexString("0200000000000000000000000000000000000000")
	ONT_ID_CONTRACT_ADDRESS, _        = AddressFromHexString("0300000000000000000000000000000000000000")
	GLOABL_PARAMS_CONTRACT_ADDRESS, _ = AddressFromHexString("0400000000000000000000000000000000000000")
	AUTH_CONTRACT_ADDRESS, _          = AddressFromHexString("0600000000000000000000000000000000000000")
	GOVERNANCE_CONTRACT_ADDRESS, _    = AddressFromHexString("0700000000000000000000000000000000000000")
)

var (
	ONT_CONTRACT_VERSION           = byte(0)
	ONG_CONTRACT_VERSION           = byte(0)
	ONT_ID_CONTRACT_VERSION        = byte(0)
	GLOBAL_PARAMS_CONTRACT_VERSION = byte(0)
	AUTH_CONTRACT_VERSION          = byte(0)
	GOVERNANCE_CONTRACT_VERSION    = byte(0)
)

const (
	UINT16_SIZE  = 2
	UINT32_SIZE  = 4
	UINT64_SIZE  = 8
	UINT256_SIZE = 32
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

var ADDRESS_EMPTY = Address{}

type Uint256 [UINT256_SIZE]byte

var UINT256_EMPTY = Uint256{}

func (u *Uint256) ToArray() []byte {
	x := make([]byte, UINT256_SIZE)
	for i := 0; i < 32; i++ {
		x[i] = byte(u[i])
	}

	return x
}

func (u *Uint256) ToHexString() string {
	return fmt.Sprintf("%x", ToArrayReverse(u[:]))
}

func (u *Uint256) Serialize(w io.Writer) error {
	_, err := w.Write(u[:])
	return err
}

func (u *Uint256) Deserialize(r io.Reader) error {
	_, err := io.ReadFull(r, u[:])
	if err != nil {
		return errors.New("deserialize Uint256 error")
	}
	return nil
}

func Uint256ParseFromBytes(f []byte) (Uint256, error) {
	if len(f) != UINT256_SIZE {
		return Uint256{}, errors.New("[Common]: Uint256ParseFromBytes err, len != 32")
	}

	var hash Uint256
	copy(hash[:], f)
	return hash, nil
}

func Uint256FromHexString(s string) (Uint256, error) {
	hx, err := HexToBytes(s)
	if err != nil {
		return UINT256_EMPTY, err
	}
	return Uint256ParseFromBytes(ToArrayReverse(hx))
}

type TransactionType byte

type MutableTransaction struct {
	Version  byte
	TxType   TransactionType
	Nonce    uint32
	GasPrice uint64
	GasLimit uint64
	Payer    Address
	Payload  Payload
	//Attributes []*TxAttribute
	attributes byte //this must be 0 now, Attribute Array length use VarUint encoding, so byte is enough for extension
	Sigs       []Sig
}

// output has no reference to self
func (self *MutableTransaction) IntoImmutable() (*Transaction, error) {
	sink := NewZeroCopySink(nil)
	err := self.serialize(sink)
	if err != nil {
		return nil, err
	}

	return TransactionFromRawBytes(sink.Bytes())
}

func (self *MutableTransaction) Hash() Uint256 {
	tx, err := self.IntoImmutable()
	if err != nil {
		return UINT256_EMPTY
	}
	return tx.Hash()
}

//GetSignatureAddresses .
func (self *MutableTransaction) GetSignatureAddresses() []Address {
	address := make([]Address, 0, len(self.Sigs))
	for _, sig := range self.Sigs {
		m := int(sig.M)
		n := len(sig.PubKeys)

		if n == 1 {
			address = append(address, AddressFromPubKey(sig.PubKeys[0]))
		} else {
			addr, err := AddressFromMultiPubKeys(sig.PubKeys, m)
			if err != nil {
				return nil
			}
			address = append(address, addr)
		}
	}
	return address
}

// Serialize the Transaction
func (tx *MutableTransaction) serialize(sink *ZeroCopySink) error {
	err := tx.serializeUnsigned(sink)
	if err != nil {
		return err
	}

	sink.WriteVarUint(uint64(len(tx.Sigs)))
	for _, sig := range tx.Sigs {
		err = sig.Serialization(sink)
		if err != nil {
			return err
		}
	}

	return nil
}

func (tx *MutableTransaction) serializeUnsigned(sink *ZeroCopySink) error {
	sink.WriteByte(byte(tx.Version))
	sink.WriteByte(byte(tx.TxType))
	sink.WriteUint32(tx.Nonce)
	sink.WriteUint64(tx.GasPrice)
	sink.WriteUint64(tx.GasLimit)
	sink.WriteBytes(tx.Payer[:])

	//Payload
	if tx.Payload == nil {
		return errors.New("transaction payload is nil")
	}
	switch pl := tx.Payload.(type) {
	case *DeployCode:
		err := pl.Serialization(sink)
		if err != nil {
			return err
		}
	case *InvokeCode:
		err := pl.Serialization(sink)
		if err != nil {
			return err
		}
	default:
		return errors.New("wrong transaction payload type")
	}
	sink.WriteVarUint(uint64(tx.attributes))

	return nil
}

// PublicKey represents a public key using an unspecified algorithm.
type PublicKey crypto.PublicKey

type Sig struct {
	SigData [][]byte
	PubKeys []PublicKey
	M       uint16
}

func (self *Sig) Serialization(sink *ZeroCopySink) error {
	temp := NewZeroCopySink(nil)
	EncodeParamProgramInto(temp, self.SigData)
	sink.WriteVarBytes(temp.Bytes())

	temp.Reset()
	if len(self.PubKeys) == 0 {
		return errors.New("no pubkeys in sig")
	} else if len(self.PubKeys) == 1 {
		EncodeSinglePubKeyProgramInto(temp, self.PubKeys[0])
	} else {
		err := EncodeMultiPubKeyProgramInto(temp, self.PubKeys, int(self.M))
		if err != nil {
			return err
		}
	}
	sink.WriteVarBytes(temp.Bytes())

	return nil
}

const MULTI_SIG_MAX_PUBKEY_SIZE = 16

func EncodeMultiPubKeyProgramInto(sink *ZeroCopySink, pubkeys []PublicKey, m int) error {
	n := len(pubkeys)
	if !(1 <= m && m <= n && n > 1 && n <= MULTI_SIG_MAX_PUBKEY_SIZE) {
		return errors.New("wrong multi-sig param")
	}

	pubkeys = SortPublicKeys(pubkeys)

	builder := ProgramBuilder{sink: sink}
	builder.PushNum(uint16(m))
	for _, pubkey := range pubkeys {
		key := SerializePublicKey(pubkey)
		builder.PushBytes(key)
	}

	builder.PushNum(uint16(len(pubkeys)))
	builder.PushOpCode(CHECKMULTISIG)
	return nil
}

func EncodeSinglePubKeyProgramInto(sink *ZeroCopySink, pubkey PublicKey) {
	builder := ProgramBuilder{sink: sink}

	builder.PushPubKey(pubkey).PushOpCode(CHECKSIG)
}

func EncodeParamProgramInto(sink *ZeroCopySink, sigs [][]byte) {
	builder := ProgramBuilder{sink: sink}
	for _, sig := range sigs {
		builder.PushBytes(sig)
	}
}

type ProgramBuilder struct {
	sink *ZeroCopySink
}

func (self *ProgramBuilder) PushNum(num uint16) *ProgramBuilder {
	if num == 0 {
		return self.PushOpCode(PUSH0)
	} else if num <= 16 {
		return self.PushOpCode(OpCode(uint8(num) - 1 + uint8(PUSH1)))
	}

	bint := big.NewInt(int64(num))
	return self.PushBytes(BigIntToNeoBytes(bint))
}

func (self *ProgramBuilder) PushOpCode(op OpCode) *ProgramBuilder {
	self.sink.WriteByte(byte(op))
	return self
}

func (self *ProgramBuilder) PushPubKey(pubkey PublicKey) *ProgramBuilder {
	buf := SerializePublicKey(pubkey)
	return self.PushBytes(buf)
}

func (self *ProgramBuilder) PushBytes(data []byte) *ProgramBuilder {
	if len(data) == 0 {
		panic("push data error: data is nil")
	}

	if len(data) <= int(PUSHBYTES75)+1-int(PUSHBYTES1) {
		self.sink.WriteByte(byte(len(data)) + byte(PUSHBYTES1) - 1)
	} else if len(data) < 0x100 {
		self.sink.WriteByte(byte(PUSHDATA1))
		self.sink.WriteUint8(uint8(len(data)))
	} else if len(data) < 0x10000 {
		self.sink.WriteByte(byte(PUSHDATA2))
		self.sink.WriteUint16(uint16(len(data)))
	} else {
		self.sink.WriteByte(byte(PUSHDATA4))
		self.sink.WriteUint32(uint32(len(data)))
	}
	self.sink.WriteBytes(data)

	return self
}

type Payload interface {
	//Serialize payload data
	Serialize(w io.Writer) error

	Deserialize(r io.Reader) error
}

var (
	VERSION_TRANSACTION = byte(0)
)

const (
	WS_SUBSCRIBE_ACTION_BLOCK         = "Block"
	WS_SUBSCRIBE_ACTION_EVENT_NOTIFY  = "Notify"
	WS_SUBSCRIBE_ACTION_EVENT_LOG     = "Log"
	WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH = "BlockTxHash"
)

// DeployCode is an implementation of transaction payload for deploy smartcontract
type DeployCode struct {
	Code        []byte
	NeedStorage bool
	Name        string
	Version     string
	Author      string
	Email       string
	Description string

	address Address
}

func (dc *DeployCode) Serialization(sink *ZeroCopySink) error {
	sink.WriteVarBytes(dc.Code)
	sink.WriteBool(dc.NeedStorage)
	sink.WriteString(dc.Name)
	sink.WriteString(dc.Version)
	sink.WriteString(dc.Author)
	sink.WriteString(dc.Email)
	sink.WriteString(dc.Description)

	return nil
}

func (dc *DeployCode) Serialize(w io.Writer) error {
	var err error

	err = WriteVarBytes(w, dc.Code)
	if err != nil {
		return fmt.Errorf("DeployCode Code Serialize failed: %s", err)
	}

	err = WriteBool(w, dc.NeedStorage)
	if err != nil {
		return fmt.Errorf("DeployCode NeedStorage Serialize failed: %s", err)
	}

	err = WriteString(w, dc.Name)
	if err != nil {
		return fmt.Errorf("DeployCode Name Serialize failed: %s", err)
	}

	err = WriteString(w, dc.Version)
	if err != nil {
		return fmt.Errorf("DeployCode Version Serialize failed: %s", err)
	}

	err = WriteString(w, dc.Author)
	if err != nil {
		return fmt.Errorf("DeployCode Author Serialize failed: %s", err)
	}

	err = WriteString(w, dc.Email)
	if err != nil {
		return fmt.Errorf("DeployCode Email Serialize failed: %s", err)
	}

	err = WriteString(w, dc.Description)
	if err != nil {
		return fmt.Errorf("DeployCode Description Serialize failed: %s", err)
	}

	return nil
}

//note: DeployCode.Code has data reference of param source
func (dc *DeployCode) Deserialization(source *ZeroCopySource) error {
	var eof, irregular bool
	dc.Code, _, irregular, eof = source.NextVarBytes()
	if irregular {
		return ErrIrregularData
	}

	dc.NeedStorage, irregular, eof = source.NextBool()
	if irregular {
		return ErrIrregularData
	}

	dc.Name, _, irregular, eof = source.NextString()
	if irregular {
		return ErrIrregularData
	}

	dc.Version, _, irregular, eof = source.NextString()
	if irregular {
		return ErrIrregularData
	}

	dc.Author, _, irregular, eof = source.NextString()
	if irregular {
		return ErrIrregularData
	}

	dc.Email, _, irregular, eof = source.NextString()
	if irregular {
		return ErrIrregularData
	}

	dc.Description, _, irregular, eof = source.NextString()
	if irregular {
		return ErrIrregularData
	}

	if eof {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func (dc *DeployCode) Deserialize(r io.Reader) error {
	code, err := ReadVarBytes(r)
	if err != nil {
		return fmt.Errorf("DeployCode Code Deserialize failed: %s", err)
	}
	dc.Code = code

	dc.NeedStorage, err = ReadBool(r)
	if err != nil {
		return fmt.Errorf("DeployCode NeedStorage Deserialize failed: %s", err)
	}

	dc.Name, err = ReadString(r)
	if err != nil {
		return fmt.Errorf("DeployCode Name Deserialize failed: %s", err)
	}

	dc.Version, err = ReadString(r)
	if err != nil {
		return fmt.Errorf("DeployCode CodeVersion Deserialize failed: %s", err)
	}

	dc.Author, err = ReadString(r)
	if err != nil {
		return fmt.Errorf("DeployCode Author Deserialize failed: %s", err)
	}

	dc.Email, err = ReadString(r)
	if err != nil {
		return fmt.Errorf("DeployCode Email Deserialize failed: %s", err)
	}

	dc.Description, err = ReadString(r)
	if err != nil {
		return fmt.Errorf("DeployCode Description Deserialize failed: %s", err)
	}

	return nil
}

const ADDR_LEN = 20

type Address [ADDR_LEN]byte

// ToBase58 returns base58 encoded address string
func (f *Address) ToBase58() string {
	data := append([]byte{23}, f[:]...)
	temp := sha256.Sum256(data)
	temps := sha256.Sum256(temp[:])
	data = append(data, temps[0:4]...)

	bi := new(big.Int).SetBytes(data).String()
	encoded, _ := base58.BitcoinEncoding.Encode([]byte(bi))
	return string(encoded)
}

// ToHexString returns  hex string representation of Address
func (f *Address) ToHexString() string {
	return fmt.Sprintf("%x", ToArrayReverse(f[:]))
}

type SmartContract DeployCode

type PreExecResult struct {
	State  byte
	Gas    uint64
	Result *ResultItem
}

func (this *PreExecResult) UnmarshalJSON(data []byte) (err error) {
	var state byte
	var gas uint64
	var resultItem *ResultItem
	defer func() {
		if err == nil {
			this.State = state
			this.Gas = gas
			this.Result = resultItem
		}
	}()

	objects := make(map[string]interface{})
	err = json.Unmarshal(data, &objects)
	if err != nil {
		return err
	}
	stateField, ok := objects["State"].(float64)
	if !ok {
		err = fmt.Errorf("Parse State field failed, type error")
		return
	}
	state = byte(stateField)

	gasField, ok := objects["Gas"].(float64)
	if !ok {
		err = fmt.Errorf("Parse Gas field failed, type error")
		return
	}
	gas = uint64(gasField)
	resultField, ok := objects["Result"]
	if !ok {
		return nil
	}
	resultItem = &ResultItem{}
	value, ok := resultField.(string)
	if ok {
		resultItem.value = value
		return nil
	}
	values, ok := resultField.([]interface{})
	if !ok {
		err = fmt.Errorf("Parse Result field, type error")
		return
	}
	resultItem.values = values
	return nil
}

type ResultItem struct {
	value  string
	values []interface{}
}

func (this *ResultItem) ToArray() ([]*ResultItem, error) {
	if this.values == nil {
		return nil, fmt.Errorf("type error")
	}
	items := make([]*ResultItem, 0)
	for _, res := range this.values {
		item := &ResultItem{}
		value, ok := res.(string)
		if ok {
			item.value = value
			items = append(items, item)
			continue
		}
		values, ok := res.([]interface{})
		if !ok {
			return nil, fmt.Errorf("parse items:%v failed, type error", res)
		}
		item.values = values
		items = append(items, item)
	}
	return items, nil
}

func (this ResultItem) ToBool() (bool, error) {
	if this.values != nil {
		return false, fmt.Errorf("type error")
	}
	return this.value == "01", nil
}

func (this ResultItem) ToInteger() (*big.Int, error) {
	data, err := this.ToByteArray()
	if err != nil {
		return nil, err
	}
	return BigIntFromNeoBytes(data), nil
}

func (this ResultItem) ToByteArray() ([]byte, error) {
	if this.values != nil {
		return nil, fmt.Errorf("type error")
	}
	return hex.DecodeString(this.value)
}

func (this ResultItem) ToString() (string, error) {
	data, err := this.ToByteArray()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

//SmartContactEvent object for event of transaction
type SmartContactEvent struct {
	TxHash      string
	State       byte
	GasConsumed uint64
	Notify      []*NotifyEventInfo
}

type NotifyEventInfo struct {
	ContractAddress string
	States          interface{}
}

func (this *NotifyEventInfo) UnmarshalJSON(data []byte) error {
	type evtInfo struct {
		ContractAddress string
		States          json.RawMessage
	}
	info := &evtInfo{}
	err := json.Unmarshal(data, info)
	if err != nil {
		return err
	}
	this.ContractAddress = info.ContractAddress

	dec := json.NewDecoder(bytes.NewReader(info.States))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim.String() != "[" {
		return this.originUnmarshal(info.States)
	}
	notifyMethod, err := dec.Token()
	if err != nil {
		return this.originUnmarshal(info.States)
	}
	if notifyMethod != "transfer" {
		return this.originUnmarshal(info.States)
	}
	transferFrom, err := dec.Token()
	if err != nil {
		return this.originUnmarshal(info.States)
	}
	transferTo, err := dec.Token()
	if err != nil {
		return this.originUnmarshal(info.States)
	}
	//using uint64 to decode, avoid precision lost decode by float64
	transferAmount := uint64(0)
	err = dec.Decode(&transferAmount)
	if err != nil {
		return this.originUnmarshal(info.States)
	}
	this.States = []interface{}{
		notifyMethod,
		transferFrom,
		transferTo,
		transferAmount,
	}
	return nil
}

func (this *NotifyEventInfo) originUnmarshal(data []byte) error {
	return json.Unmarshal(data, &this.States)
}

type SmartContractEventLog struct {
	TxHash          string
	ContractAddress string
	Message         string
}

//MerkleProof return struct
type MerkleProof struct {
	Type             string
	TransactionsRoot string
	BlockHeight      uint32
	CurBlockRoot     string
	CurBlockHeight   uint32
	TargetHashes     []string
}

type BlockTxHashes struct {
	Hash         Uint256
	Height       uint32
	Transactions []Uint256
}

type BlockTxHashesStr struct {
	Hash         string
	Height       uint32
	Transactions []string
}

type MemPoolTxState struct {
	State []*MemPoolTxStateItem
}

type MemPoolTxStateItem struct {
	Height  uint32 // The height in which tx was verified
	Type    int    // The validator flag: stateless/stateful
	ErrCode int    // Verified result
}

type MemPoolTxCount struct {
	Verified uint32 //Tx count of verified
	Verifing uint32 //Tx count of verifing
}

type GlobalParam struct {
	Key   string
	Value string
}

// param hashes will be used as workspace
func ComputeMerkleRoot(hashes []Uint256) Uint256 {
	if len(hashes) == 0 {
		return Uint256{}
	}
	sha := sha256.New()
	var temp Uint256
	for len(hashes) != 1 {
		n := len(hashes) / 2
		for i := 0; i < n; i++ {
			sha.Reset()
			sha.Write(hashes[2*i][:])
			sha.Write(hashes[2*i+1][:])
			sha.Sum(temp[:0])
			sha.Reset()
			sha.Write(temp[:])
			sha.Sum(hashes[i][:0])
		}
		if len(hashes) == 2*n+1 {
			sha.Reset()
			sha.Write(hashes[2*n][:])
			sha.Write(hashes[2*n][:])

			sha.Sum(temp[:0])
			sha.Reset()
			sha.Write(temp[:])
			sha.Sum(hashes[n][:0])

			hashes = hashes[:n+1]
		} else {
			hashes = hashes[:n]
		}
	}

	return hashes[0]
}

type OpCode byte

const (
	// Constants
	PUSH0       OpCode = 0x00 // An empty array of bytes is pushed onto the stack.
	PUSHF       OpCode = PUSH0
	PUSHBYTES1  OpCode = 0x01 // 0x01-0x4B The next opcode bytes is data to be pushed onto the stack
	PUSHBYTES75 OpCode = 0x4B
	PUSHDATA1   OpCode = 0x4C // The next byte contains the number of bytes to be pushed onto the stack.
	PUSHDATA2   OpCode = 0x4D // The next two bytes contain the number of bytes to be pushed onto the stack.
	PUSHDATA4   OpCode = 0x4E // The next four bytes contain the number of bytes to be pushed onto the stack.
	PUSHM1      OpCode = 0x4F // The number -1 is pushed onto the stack.
	PUSH1       OpCode = 0x51 // The number 1 is pushed onto the stack.
	PUSHT       OpCode = PUSH1
	PUSH2       OpCode = 0x52 // The number 2 is pushed onto the stack.
	PUSH3       OpCode = 0x53 // The number 3 is pushed onto the stack.
	PUSH4       OpCode = 0x54 // The number 4 is pushed onto the stack.
	PUSH5       OpCode = 0x55 // The number 5 is pushed onto the stack.
	PUSH6       OpCode = 0x56 // The number 6 is pushed onto the stack.
	PUSH7       OpCode = 0x57 // The number 7 is pushed onto the stack.
	PUSH8       OpCode = 0x58 // The number 8 is pushed onto the stack.
	PUSH9       OpCode = 0x59 // The number 9 is pushed onto the stack.
	PUSH10      OpCode = 0x5A // The number 10 is pushed onto the stack.
	PUSH11      OpCode = 0x5B // The number 11 is pushed onto the stack.
	PUSH12      OpCode = 0x5C // The number 12 is pushed onto the stack.
	PUSH13      OpCode = 0x5D // The number 13 is pushed onto the stack.
	PUSH14      OpCode = 0x5E // The number 14 is pushed onto the stack.
	PUSH15      OpCode = 0x5F // The number 15 is pushed onto the stack.
	PUSH16      OpCode = 0x60 // The number 16 is pushed onto the stack.

	// Flow control
	NOP      OpCode = 0x61 // Does nothing.
	JMP      OpCode = 0x62
	JMPIF    OpCode = 0x63
	JMPIFNOT OpCode = 0x64
	CALL     OpCode = 0x65
	RET      OpCode = 0x66
	APPCALL  OpCode = 0x67
	SYSCALL  OpCode = 0x68
	TAILCALL OpCode = 0x69

	// Stack
	DUPFROMALTSTACK OpCode = 0x6A
	TOALTSTACK      OpCode = 0x6B // Puts the input onto the top of the alt stack. Removes it from the main stack.
	FROMALTSTACK    OpCode = 0x6C // Puts the input onto the top of the main stack. Removes it from the alt stack.
	XDROP           OpCode = 0x6D
	DCALL           OpCode = 0x6E
	XSWAP           OpCode = 0x72
	XTUCK           OpCode = 0x73
	DEPTH           OpCode = 0x74 // Puts the number of stack items onto the stack.
	DROP            OpCode = 0x75 // Removes the top stack item.
	DUP             OpCode = 0x76 // Duplicates the top stack item.
	NIP             OpCode = 0x77 // Removes the second top stack item.
	OVER            OpCode = 0x78 // Copies the second top stack item to the top.
	PICK            OpCode = 0x79 // The item n back in the stack is copied to the top.
	ROLL            OpCode = 0x7A // The item n back in the stack is moved to the top.
	ROT             OpCode = 0x7B // Move third top item on the top of stack.
	SWAP            OpCode = 0x7C // The top two items on the stack are swapped.
	TUCK            OpCode = 0x7D // The item at the top of the stack is copied and inserted before the second-to-top item.

	// Splice
	CAT    OpCode = 0x7E // Concatenates two strings.
	SUBSTR OpCode = 0x7F // Returns a section of a string.
	LEFT   OpCode = 0x80 // Keeps only characters left of the specified point in a string.
	RIGHT  OpCode = 0x81 // Keeps only characters right of the specified point in a string.
	SIZE   OpCode = 0x82 // Returns the length of the input string.

	// Bitwise logic
	INVERT OpCode = 0x83 // Flips all of the bits in the input.
	AND    OpCode = 0x84 // Boolean and between each bit in the inputs.
	OR     OpCode = 0x85 // Boolean or between each bit in the inputs.
	XOR    OpCode = 0x86 // Boolean exclusive or between each bit in the inputs.
	EQUAL  OpCode = 0x87 // Returns 1 if the inputs are exactly equal, 0 otherwise.
	// EQUALVERIFY = 0x88 // Same as EQUAL, but runs VERIFY afterward.
	// RESERVED1 = 0x89 // Transaction is invalid unless occurring in an unexecuted IF branch
	// RESERVED2 = 0x8A // Transaction is invalid unless occurring in an unexecuted IF branch

	// Arithmetic
	// Note: Arithmetic inputs are limited to signed 32-bit integers, but may overflow their output.
	INC         OpCode = 0x8B // 1 is added to the input.
	DEC         OpCode = 0x8C // 1 is subtracted from the input.
	SIGN        OpCode = 0x8D
	NEGATE      OpCode = 0x8F // The sign of the input is flipped.
	ABS         OpCode = 0x90 // The input is made positive.
	NOT         OpCode = 0x91 // If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
	NZ          OpCode = 0x92 // Returns 0 if the input is 0. 1 otherwise.
	ADD         OpCode = 0x93 // a is added to b.
	SUB         OpCode = 0x94 // b is subtracted from a.
	MUL         OpCode = 0x95 // a is multiplied by b.
	DIV         OpCode = 0x96 // a is divided by b.
	MOD         OpCode = 0x97 // Returns the remainder after dividing a by b.
	SHL         OpCode = 0x98 // Shifts a left b bits, preserving sign.
	SHR         OpCode = 0x99 // Shifts a right b bits, preserving sign.
	BOOLAND     OpCode = 0x9A // If both a and b are not 0, the output is 1. Otherwise 0.
	BOOLOR      OpCode = 0x9B // If a or b is not 0, the output is 1. Otherwise 0.
	NUMEQUAL    OpCode = 0x9C // Returns 1 if the numbers are equal, 0 otherwise.
	NUMNOTEQUAL OpCode = 0x9E // Returns 1 if the numbers are not equal, 0 otherwise.
	LT          OpCode = 0x9F // Returns 1 if a is less than b, 0 otherwise.
	GT          OpCode = 0xA0 // Returns 1 if a is greater than b, 0 otherwise.
	LTE         OpCode = 0xA1 // Returns 1 if a is less than or equal to b, 0 otherwise.
	GTE         OpCode = 0xA2 // Returns 1 if a is greater than or equal to b, 0 otherwise.
	MIN         OpCode = 0xA3 // Returns the smaller of a and b.
	MAX         OpCode = 0xA4 // Returns the larger of a and b.
	WITHIN      OpCode = 0xA5 // Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.

	// Crypto
	//RIPEMD160 = 0xA6 // The input is hashed using RIPEMD-160.
	SHA1          OpCode = 0xA7 // The input is hashed using SHA-1.
	SHA256        OpCode = 0xA8 // The input is hashed using SHA-256.
	HASH160       OpCode = 0xA9
	HASH256       OpCode = 0xAA
	CHECKSIG      OpCode = 0xAC // The entire transaction's outputs inputs and script (from the most recently-executed CODESEPARATOR to the end) are hashed. The signature used by CHECKSIG must be a valid signature for this hash and public key. If it is 1 is returned 0 otherwise.
	VERIFY        OpCode = 0xAD
	CHECKMULTISIG OpCode = 0xAE // For each signature and public key pair CHECKSIG is executed. If more public keys than signatures are listed some key/sig pairs can fail. All signatures need to match a public key. If all signatures are valid 1 is returned 0 otherwise. Due to a bug one extra unused value is removed from the stack.

	// Array
	ARRAYSIZE OpCode = 0xC0
	PACK      OpCode = 0xC1
	UNPACK    OpCode = 0xC2
	PICKITEM  OpCode = 0xC3
	SETITEM   OpCode = 0xC4
	NEWARRAY  OpCode = 0xC5
	NEWSTRUCT OpCode = 0xC6
	NEWMAP    OpCode = 0xC7
	APPEND    OpCode = 0xC8
	REVERSE   OpCode = 0xC9
	REMOVE    OpCode = 0xCA
	HASKEY    OpCode = 0xCB
	KEYS      OpCode = 0xCC
	VALUES    OpCode = 0xCD

	//Exception
	THROW      = 0xF0
	THROWIFNOT = 0xF1
)

type State struct {
	From  Address
	To    Address
	Value uint64
}

func (this *State) Serialize(w io.Writer) error {
	if err := WriteAddress(w, this.From); err != nil {
		return fmt.Errorf("[State] serialize from error:%v", err)
	}
	if err := WriteAddress(w, this.To); err != nil {
		return fmt.Errorf("[State] serialize to error:%v", err)
	}
	if err := WriteVarUint(w, this.Value); err != nil {
		return fmt.Errorf("[State] serialize value error:%v", err)
	}
	return nil
}

func (this *State) Serialization(sink *ZeroCopySink) {
	EncodeAddress(sink, this.From)
	EncodeAddress(sink, this.To)
	EncodeVarUint(sink, this.Value)
}

func (this *State) Deserialize(r io.Reader) error {
	var err error
	this.From, err = ReadAddress(r)
	if err != nil {
		return fmt.Errorf("[State] deserialize from error:%v", err)
	}
	this.To, err = ReadAddress(r)
	if err != nil {
		return fmt.Errorf("[State] deserialize to error:%v", err)
	}

	this.Value, err = ReadVarUintAddress(r)
	if err != nil {
		return err
	}
	return nil
}

func (this *State) Deserialization(source *ZeroCopySource) error {
	var err error
	this.From, err = DecodeAddress(source)
	if err != nil {
		return err
	}

	this.To, err = DecodeAddress(source)
	if err != nil {
		return err
	}

	this.Value, err = DecodeVarUint(source)

	return err
}

type PrivateKeyBytes []byte

func (priv PrivateKeyBytes) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

type PublicKeyBytes []byte

type PrivateKey interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
}

type cryptoPrivateKey interface{}
type cryptoPublicKey interface{}

type SignatureScheme byte

type Signer interface {
	Sign(data []byte) ([]byte, error)
	GetPublicKey() PublicKey
	GetPrivateKey() PrivateKey
	GetSigScheme() SignatureScheme
}

/* crypto object */
type Account struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
	Address    Address
	SigScheme  SignatureScheme
}

func ConstructPrivateKey(data []byte, curve elliptic.Curve) *ecdsa.PrivateKey {
	d := new(big.Int).SetBytes(data)
	x, y := curve.ScalarBaseMult(data)

	return &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: curve,
		},
	}
}

func NewAccountFromPrivateKey(privateKey []byte, signatureScheme SignatureScheme) (*Account, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("privatekey should not be nil")
	}
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("the length of privatekey should be 32")
	}
	prikey := ConstructPrivateKey(privateKey, elliptic.P256())
	privaKey := ECPrivateKey{
		Algorithm:  ECDSA,
		PrivateKey: prikey,
	}
	address := AddressFromPubKey(privaKey.Public())
	return &Account{
		PrivateKey: &privaKey,
		PublicKey:  privaKey.Public(),
		Address:    address,
		SigScheme:  signatureScheme,
	}, nil
}

const (
	SHA224withECDSA SignatureScheme = iota
	SHA256withECDSA
	SHA384withECDSA
	SHA512withECDSA
	SHA3_224withECDSA
	SHA3_256withECDSA
	SHA3_384withECDSA
	SHA3_512withECDSA
	RIPEMD160withECDSA

	SM3withSM2

	SHA512withEDDSA
)

func NewAccount(sigscheme ...SignatureScheme) *Account {
	var scheme SignatureScheme
	if len(sigscheme) == 0 {
		scheme = SHA256withECDSA
	} else {
		scheme = sigscheme[0]
	}
	var pkAlgorithm KeyType
	var params interface{}
	switch scheme {
	case SHA224withECDSA, SHA3_224withECDSA:
		pkAlgorithm = PK_ECDSA
		params = P224
	case SHA256withECDSA, SHA3_256withECDSA, RIPEMD160withECDSA:
		pkAlgorithm = PK_ECDSA
		params = P256
	case SHA384withECDSA, SHA3_384withECDSA:
		pkAlgorithm = PK_ECDSA
		params = P384
	case SHA512withECDSA, SHA3_512withECDSA:
		pkAlgorithm = PK_ECDSA
		params = P521
	case SM3withSM2:
		pkAlgorithm = PK_SM2
		params = SM2P256V1
	case SHA512withEDDSA:
		pkAlgorithm = PK_EDDSA
		params = ED25519
	default:
		return nil
	}
	pri, pub, _ := GenerateKeyPair(pkAlgorithm, params)
	address := AddressFromPubKey(pub)
	return &Account{
		PrivateKey: pri,
		PublicKey:  pub,
		Address:    address,
		SigScheme:  scheme,
	}
}

func (this *Account) Sign(data []byte) ([]byte, error) {
	sig, err := Sign(this.SigScheme, this.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	sigData, err := Serialize(sig)
	if err != nil {
		return nil, fmt.Errorf("signature.Serialize error:%s", err)
	}
	return sigData, nil
}

func (this *Account) GetPrivateKey() PrivateKey {
	return this.PrivateKey
}

func (this *Account) GetPublicKey() PublicKey {
	return this.PublicKey
}

func (this *Account) GetSigScheme() SignatureScheme {
	return this.SigScheme
}

func Serialize(sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("failed serializing signature: input is nil")
	}

	var buf bytes.Buffer
	buf.WriteByte(byte(sig.Scheme))
	switch v := sig.Value.(type) {
	case *DSASignature:
		if sig.Scheme != SHA224withECDSA &&
			sig.Scheme != SHA256withECDSA &&
			sig.Scheme != SHA384withECDSA &&
			sig.Scheme != SHA512withECDSA &&
			sig.Scheme != SHA3_224withECDSA &&
			sig.Scheme != SHA3_256withECDSA &&
			sig.Scheme != SHA3_384withECDSA &&
			sig.Scheme != SHA3_512withECDSA &&
			sig.Scheme != RIPEMD160withECDSA {
			return nil, errors.New("failed serializing signature: unmatched signature scheme and value")
		}
		buf.Write(serializeDSA(v))

	case *SM2Signature:
		if sig.Scheme != SM3withSM2 {
			return nil, errors.New("failed serializing signature: unmatched signature scheme and value")
		}
		buf.Write([]byte(v.ID))
		buf.WriteByte(byte(0))
		buf.Write(serializeDSA(&v.DSASignature))
	case []byte:
		buf.Write(v)
	default:
		return nil, errors.New("failed serializing signature: unrecognized signature type")
	}

	res := buf.Bytes()

	// Treat SHA256withECDSA as a special case, using the signature
	// data directly without the signature scheme.
	if sig.Scheme == SHA256withECDSA && len(res) == 65 {
		res = res[1:]
	}

	return res, nil
}

func serializeDSA(sig *DSASignature) []byte {
	if sig == nil || sig.R == nil || sig.S == nil {
		panic("serializeDSA: invalid argument")
	}

	size := (sig.Curve.Params().BitSize + 7) >> 3
	res := make([]byte, size*2)

	r := sig.R.Bytes()
	s := sig.S.Bytes()
	copy(res[size-len(r):], r)
	copy(res[size*2-len(s):], s)
	return res
}

type SM2Curve interface {
	elliptic.Curve

	// ABytes returns the little endian byte sequence of parameter A.
	ABytes() []byte
}
