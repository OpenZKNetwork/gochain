package script

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/dynamicgo/slf4go"
	"github.com/dynamicgo/xerrors"

	// "github.com/openzknetwork/gochain/rpc/ont"

	"golang.org/x/crypto/ripemd160"
)

// Script .
type Script struct {
	slf4go.Logger
	Ops   []*Op
	Name  string
	Error error
}

var (
	ONT_CONTRACT_ADDRESS, _           = AddressFromHexString("0100000000000000000000000000000000000000")
	ONG_CONTRACT_ADDRESS, _           = AddressFromHexString("0200000000000000000000000000000000000000")
	ONT_ID_CONTRACT_ADDRESS, _        = AddressFromHexString("0300000000000000000000000000000000000000")
	GLOABL_PARAMS_CONTRACT_ADDRESS, _ = AddressFromHexString("0400000000000000000000000000000000000000")
	AUTH_CONTRACT_ADDRESS, _          = AddressFromHexString("0600000000000000000000000000000000000000")
	GOVERNANCE_CONTRACT_ADDRESS, _    = AddressFromHexString("0700000000000000000000000000000000000000")
)

// New create new script with display name
func New(name string) *Script {
	return &Script{
		Logger: slf4go.Get("neogo-script"),
		Name:   name,
	}
}

// Reset .
func (script *Script) Reset() {
	script.Ops = nil
	script.Error = nil
}

// Emit emit one op
func (script *Script) Emit(opcode OpCode, arg []byte) *Script {

	if !script.checkEmit() {
		return script
	}

	op := &Op{
		Code: opcode,
		Arg:  arg,
	}

	script.DebugF("emit %s", op)

	script.Ops = append(script.Ops, op)

	return script
}

// EmitJump .
func (script *Script) EmitJump(op OpCode, offset int16) *Script {
	if op != JMP && op != JMPIF && op != JMPIFNOT && op != CALL {
		script.Error = fmt.Errorf("[%d] invalid EmitJump opcode %s", len(script.Ops), op2Strings[op])
		return script
	}

	data := make([]byte, 2)

	binary.LittleEndian.PutUint16(data, uint16(offset))

	script.Emit(op, data)

	return script
}

// EmitAPPCall .
func (script *Script) EmitAPPCall(scriptHash []byte, tailCall bool) *Script {
	if len(scriptHash) != 20 {
		script.Error = fmt.Errorf("[%d] EmitAPPCall scriptHash length must be 20 bytes", len(script.Ops))
		return script
	}

	if tailCall {
		return script.Emit(TAILCALL, scriptHash)
	}

	return script.Emit(APPCALL, scriptHash)
}

// EmitPushInteger .
func (script *Script) EmitPushInteger(number *big.Int) *Script {
	if number.Int64() == -1 {
		return script.Emit(PUSHM1, nil)
	}

	if number.Int64() == 0 {
		return script.Emit(PUSH0, nil)
	}

	if number.Int64() > 0 && number.Int64() <= 16 {
		return script.Emit(OpCode(byte(PUSH1)-1+byte(number.Int64())), nil)
	}

	data := reverseBytes(number.Bytes())

	if number.Int64() > 0 {
		data = append(data, 0x00)
	} else {
		data = append(data, 0x80)
	}

	return script.EmitPushBytes(data)
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

// EmitPushBool .
func (script *Script) EmitPushBool(data bool) *Script {
	if data {
		return script.Emit(PUSHT, nil)
	}

	return script.Emit(PUSHF, nil)
}

// EmitPushString .
func (script *Script) EmitPushString(data string) *Script {
	return script.EmitPushBytes([]byte(data))
}

// EmitPushBytes .
func (script *Script) EmitPushBytes(data []byte) *Script {

	if script.Error != nil {
		return script
	}

	if data == nil {
		script.Error = fmt.Errorf("[%d] EmitPushBytes args can't be null", len(script.Ops))
		return script
	}

	if len(data) < int(PUSHBYTES75) {
		return script.Emit(OpCode(len(data)), data)
	}

	if len(data) < int(0x100) {

		var buff bytes.Buffer
		buff.Write([]byte{byte(len(data))})
		buff.Write(data)

		script.Emit(PUSHDATA1, buff.Bytes())

		return script
	}

	if len(data) < int(0x10000) {
		var buff bytes.Buffer

		bytesOfLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(bytesOfLength, uint16(len(data)))

		buff.Write(bytesOfLength)
		buff.Write(data)

		script.Emit(PUSHDATA2, buff.Bytes())

		return script
	}

	var buff bytes.Buffer

	bytesOfLength := make([]byte, 4)

	binary.LittleEndian.PutUint32(bytesOfLength, uint32(len(data)))

	buff.Write(bytesOfLength)
	buff.Write(data)

	script.Emit(PUSHDATA4, buff.Bytes())

	return script
}

// EmitSysCall .
func (script *Script) EmitSysCall(api string) *Script {
	if api == "" {
		script.Error = fmt.Errorf("[%d] EmitSysCall api parameter can't be empty", len(script.Ops))
	}

	bytesOfAPI := []byte(api)

	if len(bytesOfAPI) > 252 {
		script.Error = fmt.Errorf("[%d] EmitSysCall api name can't longer than 252", len(script.Ops))
	}

	return script.Emit(SYSCALL, append([]byte{byte(len(bytesOfAPI))}, bytesOfAPI...))
}

func (script *Script) checkEmit() bool {
	return script.Error == nil
}

func (script *Script) Write(writer io.Writer) error {

	if script.Error != nil {
		return script.Error
	}

	for _, op := range script.Ops {
		_, err := writer.Write(append([]byte{byte(op.Code)}, op.Arg...))

		if err != nil {
			return err
		}
	}

	return nil
}

// Bytes get script bytes
func (script *Script) Bytes() ([]byte, error) {
	var buff bytes.Buffer

	if err := script.Write(&buff); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// Hash get script hash
func (script *Script) Hash() ([]byte, error) {

	buff, err := script.Bytes()

	if err != nil {
		return nil, err
	}

	/* SHA256 Hash */
	sha256h := sha256.New()
	sha256h.Reset()
	sha256h.Write(buff)
	pubhash1 := sha256h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160h := ripemd160.New()
	ripemd160h.Reset()
	ripemd160h.Write(pubhash1)
	pubhash2 := ripemd160h.Sum(nil)

	programhash := pubhash2

	return programhash, nil
}

// Hash .
func Hash(script []byte) []byte {
	/* SHA256 Hash */
	sha256h := sha256.New()
	sha256h.Reset()
	sha256h.Write(script)
	pubhash1 := sha256h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160h := ripemd160.New()
	ripemd160h.Reset()
	ripemd160h.Write(pubhash1)
	pubhash2 := ripemd160h.Sum(nil)

	programhash := pubhash2

	return programhash
}

// JSON .
func (script *Script) JSON() string {
	var ops []string

	for _, op := range script.Ops {
		ops = append(ops, op.String())
	}

	jsondata, _ := json.Marshal(ops)

	return string(jsondata)
}

const ADDR_LEN = 20

type Address [ADDR_LEN]byte

func (f *Address) ToHexString() string {
	return fmt.Sprintf("%x", ToArrayReverse(f[:]))
}

func ToArrayReverse(arr []byte) []byte {
	l := len(arr)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, arr[i])
	}
	return x
}

var ADDRESS_EMPTY = Address{}

func AddressFromHexString(s string) (Address, error) {
	hx, err := hex.DecodeString(s)
	if err != nil {
		return ADDRESS_EMPTY, err
	}
	l := len(hx)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, hx[i])
	}

	if len(x) != ADDR_LEN {
		return ADDRESS_EMPTY, errors.New("[Common]: AddressParseFromBytes err, len != 20")
	}

	var addr Address
	copy(addr[:], x)
	return addr, nil
}

func (script *Script) NewScript(contractAddress, from, to string, version byte, method string, amount uint64) ([]byte, error) {
	contractAddr, err := AddressFromHexString(contractAddress)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse contract address error")
	}
	fromAddr, err := AddressFromHexString(from)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse from address error")
	}
	toAddr, err := AddressFromHexString(to)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse to address error")
	}
	type State struct {
		From  Address
		To    Address
		Value uint64
	}
	state := &State{
		From:  fromAddr,
		To:    toAddr,
		Value: amount,
	}
	params := []interface{}{[]*State{state}}

	if contractAddress != ONT_CONTRACT_ADDRESS.ToHexString() && contractAddress != ONG_CONTRACT_ADDRESS.ToHexString() {
		params = []interface{}{"transfer", []interface{}{fromAddr, toAddr, big.NewInt(int64(amount))}}
		return script.NewNeoVMScript(contractAddress, params)
	}
	return script.BuildInvokeCode(contractAddr, method, params)
}

// NewNeoVMScript .
func (script *Script) NewNeoVMScript(contractAddress string, params []interface{}) ([]byte, error) {
	contractAddr, err := AddressFromHexString(contractAddress)
	if err != nil {
		return nil, xerrors.Wrapf(err, "parse contract address error")
	}
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	if len(params) == 0 {
		params = append(params, "")
	}

	err = script.BuildNeoVMParam(params)
	if err != nil {
		return nil, err
	}
	return BuildNeoVMInvokeCode(script, contractAddr)
}

func (script *Script) BuildInvokeCode(contractAddress Address, method string, params []interface{}) ([]byte, error) {

	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	if len(params) == 0 {
		params = append(params, "")
	}

	err := script.BuildNeoVMParam(params)
	if err != nil {
		return nil, err
	}

	script.EmitPushBytes([]byte(method))
	script.EmitPushBytes(contractAddress[:])
	script.EmitPushInteger(new(big.Int).SetInt64(int64(byte(0))))
	script.Emit(SYSCALL, nil)
	script.EmitPushBytes([]byte(NATIVE_INVOKE_NAME))

	return script.Bytes()
}

var NATIVE_INVOKE_NAME = "Ontology.Native.Invoke"

const (
	UINT16_SIZE  = 2
	UINT32_SIZE  = 4
	UINT64_SIZE  = 8
	UINT256_SIZE = 32
)

type Uint256 [UINT256_SIZE]byte

func (u *Uint256) ToArray() []byte {
	x := make([]byte, UINT256_SIZE)
	for i := 0; i < 32; i++ {
		x[i] = byte(u[i])
	}

	return x
}
func BuildNeoVMInvokeCode(builder *Script, smartContractAddress Address) ([]byte, error) {
	b, err := builder.Bytes()
	if err != nil {
		return nil, err
	}
	args := append(b, APPCALL)
	args = append(args, smartContractAddress[:]...)
	return args, nil
}

//buildNeoVMParamInter build neovm invoke param code
func (script *Script) BuildNeoVMParam(smartContractParams []interface{}) error {
	//VM load params in reverse order
	for i := len(smartContractParams) - 1; i >= 0; i-- {
		switch v := smartContractParams[i].(type) {
		case bool:
			script.EmitPushBool(v)
		case byte:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case int:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case uint:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case int32:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case uint32:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case int64:
			script.EmitPushInteger(big.NewInt(int64(v)))
		case Fixed64:
			script.EmitPushInteger(big.NewInt(int64(v.GetData())))
		case uint64:
			val := big.NewInt(0)
			script.EmitPushInteger(val.SetUint64(uint64(v)))
		case string:
			script.EmitPushBytes([]byte(v))
		case *big.Int:
			script.EmitPushInteger(v)
		case []byte:
			script.EmitPushBytes(v)
		case Address:
			script.EmitPushBytes(v[:])
		case Uint256:
			script.EmitPushBytes(v.ToArray())
		case []interface{}:
			err := script.BuildNeoVMParam(v)
			if err != nil {
				return err
			}
			script.EmitPushInteger(big.NewInt(int64(len(v))))
			script.Emit(PACK, nil)
		default:
			object := reflect.ValueOf(v)
			kind := object.Kind().String()
			if kind == "ptr" {
				object = object.Elem()
				kind = object.Kind().String()
			}
			switch kind {
			case "slice":
				ps := make([]interface{}, 0)
				for i := 0; i < object.Len(); i++ {
					ps = append(ps, object.Index(i).Interface())
				}
				err := script.BuildNeoVMParam([]interface{}{ps})
				if err != nil {
					return err
				}
			case "struct":
				script.EmitPushInteger(big.NewInt(0))
				script.Emit(NEWSTRUCT, nil)
				script.Emit(TOALTSTACK, nil)
				for i := 0; i < object.NumField(); i++ {
					field := object.Field(i)
					script.Emit(DUPFROMALTSTACK, nil)
					err := script.BuildNeoVMParam([]interface{}{field.Interface()})
					if err != nil {
						return err
					}
					script.Emit(APPEND, nil)
				}
				script.Emit(FROMALTSTACK, nil)
			default:
				return fmt.Errorf("unsupported param:%s", v)
			}
		}
	}
	return nil
}

type Fixed64 int64

func (f Fixed64) GetData() int64 {
	return int64(f)
}
