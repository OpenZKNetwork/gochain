package ont

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// transaction constants
const TX_MAX_SIG_SIZE = 16

const (
	Bookkeeper TransactionType = 0x02
	Deploy     TransactionType = 0xd0
	Invoke     TransactionType = 0xd1
)

type Block struct {
	Header       *Header
	Transactions []*Transaction
}

func (bd *Header) Deserialization(source *ZeroCopySource) error {
	err := bd.deserializationUnsigned(source)
	if err != nil {
		return err
	}

	n, _, irregular, eof := source.NextVarUint()
	if eof {
		return io.ErrUnexpectedEOF
	}
	if irregular {
		return ErrIrregularData
	}

	for i := 0; i < int(n); i++ {
		buf, _, irregular, eof := source.NextVarBytes()
		if eof {
			return io.ErrUnexpectedEOF
		}
		if irregular {
			return ErrIrregularData
		}
		pubkey, err := DeserializePublicKey(buf)
		if err != nil {
			return err
		}
		bd.Bookkeepers = append(bd.Bookkeepers, pubkey)
	}

	m, _, irregular, eof := source.NextVarUint()
	if eof {
		return io.ErrUnexpectedEOF
	}
	if irregular {
		return ErrIrregularData
	}

	for i := 0; i < int(m); i++ {
		sig, _, irregular, eof := source.NextVarBytes()
		if eof {
			return io.ErrUnexpectedEOF
		}
		if irregular {
			return ErrIrregularData
		}
		bd.SigData = append(bd.SigData, sig)
	}

	return nil
}

func (bd *Header) deserializationUnsigned(source *ZeroCopySource) error {
	var irregular, eof bool

	bd.Version, eof = source.NextUint32()
	bd.PrevBlockHash, eof = source.NextHash()
	bd.TransactionsRoot, eof = source.NextHash()
	bd.BlockRoot, eof = source.NextHash()
	bd.Timestamp, eof = source.NextUint32()
	bd.Height, eof = source.NextUint32()
	bd.ConsensusData, eof = source.NextUint64()

	bd.ConsensusPayload, _, irregular, eof = source.NextVarBytes()
	if irregular {
		return ErrIrregularData
	}

	bd.NextBookkeeper, eof = source.NextAddress()
	if eof {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (bd *Header) Hash() Uint256 {
	if bd.hash != nil {
		return *bd.hash
	}
	sink := NewZeroCopySink(nil)
	bd.serializationUnsigned(sink)
	temp := sha256.Sum256(sink.Bytes())
	hash := Uint256(sha256.Sum256(temp[:]))

	bd.hash = &hash
	return hash
}

//Serialize the blockheader data without program
func (bd *Header) serializationUnsigned(sink *ZeroCopySink) {
	sink.WriteUint32(bd.Version)
	sink.WriteBytes(bd.PrevBlockHash[:])
	sink.WriteBytes(bd.TransactionsRoot[:])
	sink.WriteBytes(bd.BlockRoot[:])
	sink.WriteUint32(bd.Timestamp)
	sink.WriteUint32(bd.Height)
	sink.WriteUint64(bd.ConsensusData)
	sink.WriteVarBytes(bd.ConsensusPayload)
	sink.WriteBytes(bd.NextBookkeeper[:])
}

var ErrIrregularData = errors.New("irregular data")

// if no error, ownership of param raw is transfered to Transaction
func BlockFromRawBytes(raw []byte) (*Block, error) {
	source := NewZeroCopySource(raw)
	block := &Block{}
	err := block.Deserialization(source)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (self *Block) Deserialization(source *ZeroCopySource) error {
	if self.Header == nil {
		self.Header = new(Header)
	}
	err := self.Header.Deserialization(source)
	if err != nil {
		return err
	}

	length, eof := source.NextUint32()
	if eof {
		return io.ErrUnexpectedEOF
	}

	var hashes []Uint256
	mask := make(map[Uint256]bool)
	for i := uint32(0); i < length; i++ {
		transaction := new(Transaction)
		// note currently all transaction in the block shared the same source
		err := transaction.Deserialization(source)
		if err != nil {
			return err
		}
		txhash := transaction.Hash()
		if mask[txhash] {
			return errors.New("duplicated transaction in block")
		}
		mask[txhash] = true
		hashes = append(hashes, txhash)
		self.Transactions = append(self.Transactions, transaction)
	}

	root := ComputeMerkleRoot(hashes)
	if self.Header.TransactionsRoot != root {
		return errors.New("mismatched transaction root")
	}

	return nil
}

// InvokeCode is an implementation of transaction payload for invoke smartcontract
type InvokeCode struct {
	Code []byte
}

func (self *InvokeCode) Serialization(sink *ZeroCopySink) error {
	sink.WriteVarBytes(self.Code)
	return nil
}

func (self *InvokeCode) Serialize(w io.Writer) error {
	if err := WriteVarBytes(w, self.Code); err != nil {
		return fmt.Errorf("InvokeCode Code Serialize failed: %s", err)
	}
	return nil
}

//note: InvokeCode.Code has data reference of param source
func (self *InvokeCode) Deserialization(source *ZeroCopySource) error {
	code, _, irregular, eof := source.NextVarBytes()
	if eof {
		return io.ErrUnexpectedEOF
	}
	if irregular {
		return ErrIrregularData
	}

	self.Code = code
	return nil
}

func (self *InvokeCode) Deserialize(r io.Reader) error {
	code, err := ReadVarBytes(r)
	if err != nil {
		return fmt.Errorf("InvokeCode Code Deserialize failed: %s", err)
	}
	self.Code = code
	return nil
}

type Header struct {
	Version          uint32
	PrevBlockHash    Uint256
	TransactionsRoot Uint256
	BlockRoot        Uint256
	Timestamp        uint32
	Height           uint32
	ConsensusData    uint64
	ConsensusPayload []byte
	NextBookkeeper   Address

	//Program *program.Program
	Bookkeepers []PublicKey
	SigData     [][]byte

	hash *Uint256
}

const MAX_TX_SIZE = 1024 * 1024 // The max size of a transaction to prevent DOS attacks

type Transaction struct {
	Version  byte
	TxType   TransactionType
	Nonce    uint32
	GasPrice uint64
	GasLimit uint64
	Payer    Address
	Payload  Payload
	//Attributes []*TxAttribute
	attributes byte //this must be 0 now, Attribute Array length use VarUint encoding, so byte is enough for extension
	Sigs       []RawSig

	Raw []byte // raw transaction data

	hash       Uint256
	SignedAddr []Address // this is assigned when passed signature verification

	nonDirectConstracted bool // used to check literal construction like `tx := &Transaction{...}`
}

func (tx *Transaction) ToArray() []byte {
	b := new(bytes.Buffer)
	tx.Serialize(b)
	return b.Bytes()
}

func (tx *Transaction) Hash() Uint256 {
	return tx.hash
}

// Serialize the Transaction
func (tx *Transaction) Serialize(w io.Writer) error {
	if tx.nonDirectConstracted == false || len(tx.Raw) == 0 {
		panic("wrong constructed transaction")
	}
	_, err := w.Write(tx.Raw)
	return err
}

type InventoryType byte

const (
	TRANSACTION InventoryType = 0x01
	BLOCK       InventoryType = 0x02
	CONSENSUS   InventoryType = 0xe0
)

func (tx *Transaction) Type() InventoryType {
	return TRANSACTION
}

func (tx *Transaction) deserializationUnsigned(source *ZeroCopySource) error {
	var irregular, eof bool
	tx.Version, eof = source.NextByte()
	var txtype byte
	txtype, eof = source.NextByte()
	tx.TxType = TransactionType(txtype)
	tx.Nonce, eof = source.NextUint32()
	tx.GasPrice, eof = source.NextUint64()
	tx.GasLimit, eof = source.NextUint64()
	var buf []byte
	buf, eof = source.NextBytes(ADDR_LEN)
	if eof {
		return io.ErrUnexpectedEOF
	}
	copy(tx.Payer[:], buf)

	switch tx.TxType {
	case Invoke:
		pl := new(InvokeCode)
		err := pl.Deserialization(source)
		if err != nil {
			return err
		}
		tx.Payload = pl
	case Deploy:
		pl := new(DeployCode)
		err := pl.Deserialization(source)
		if err != nil {
			return err
		}
		tx.Payload = pl
	default:
		return fmt.Errorf("unsupported tx type %v", tx.Type())
	}

	var length uint64
	length, _, irregular, eof = source.NextVarUint()
	if irregular {
		return ErrIrregularData
	}
	if eof {
		return io.ErrUnexpectedEOF
	}

	if length != 0 {
		return fmt.Errorf("transaction attribute must be 0, got %d", length)
	}
	tx.attributes = 0

	return nil
}

// Transaction has internal reference of param `source`
func (tx *Transaction) Deserialization(source *ZeroCopySource) error {
	pstart := source.Pos()
	err := tx.deserializationUnsigned(source)
	if err != nil {
		return err
	}
	pos := source.Pos()
	lenUnsigned := pos - pstart
	source.BackUp(lenUnsigned)
	rawUnsigned, _ := source.NextBytes(lenUnsigned)
	temp := sha256.Sum256(rawUnsigned)
	tx.hash = Uint256(sha256.Sum256(temp[:]))

	// tx sigs
	length, _, irregular, eof := source.NextVarUint()
	if irregular {
		return ErrIrregularData
	}
	if eof {
		return io.ErrUnexpectedEOF
	}
	if length > TX_MAX_SIG_SIZE {
		return fmt.Errorf("transaction signature number %d execced %d", length, TX_MAX_SIG_SIZE)
	}

	for i := 0; i < int(length); i++ {
		var sig RawSig
		err := sig.Deserialization(source)
		if err != nil {
			return err
		}

		tx.Sigs = append(tx.Sigs, sig)
	}

	pend := source.Pos()
	lenAll := pend - pstart
	if lenAll > MAX_TX_SIZE {
		return fmt.Errorf("execced max transaction size:%d", lenAll)
	}
	source.BackUp(lenAll)
	tx.Raw, _ = source.NextBytes(lenAll)

	tx.nonDirectConstracted = true

	return nil
}

type RawSig struct {
	Invoke []byte
	Verify []byte
}

func (self *RawSig) Deserialization(source *ZeroCopySource) error {
	var eof, irregular bool
	self.Invoke, _, irregular, eof = source.NextVarBytes()
	if irregular {
		return ErrIrregularData
	}
	self.Verify, _, irregular, eof = source.NextVarBytes()
	if irregular {
		return ErrIrregularData
	}

	if eof {
		return io.ErrUnexpectedEOF
	}

	return nil
}

func GetVersion(data []byte) (string, error) {
	version := ""
	err := json.Unmarshal(data, &version)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return version, nil
}

func GetBlock(data []byte) (*Block, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	blockData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return BlockFromRawBytes(blockData)
}

func GetUint32(data []byte) (uint32, error) {
	count := uint32(0)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count, nil
}

func GetUint64(data []byte) (uint64, error) {
	count := uint64(0)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count, nil
}

func GetInt(data []byte) (int, error) {
	integer := 0
	err := json.Unmarshal(data, &integer)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return integer, nil
}

func GetUint256(data []byte) (Uint256, error) {
	hexHash := ""
	err := json.Unmarshal(data, &hexHash)
	if err != nil {
		return Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := Uint256FromHexString(hexHash)
	if err != nil {
		return Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

func GetTransaction(data []byte) (*Transaction, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	txData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return TransactionFromRawBytes(txData)
}

func TransactionFromRawBytes(raw []byte) (*Transaction, error) {
	if len(raw) > MAX_TX_SIZE {
		return nil, errors.New("execced max transaction size")
	}
	source := NewZeroCopySource(raw)
	tx := &Transaction{Raw: raw}
	err := tx.Deserialization(source)
	if err != nil {
	
		return nil, err
	}
	
	return tx, nil
}

func GetStorage(data []byte) ([]byte, error) {
	hexData := ""
	err := json.Unmarshal(data, &hexData)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	value, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return value, nil
}

func GetSmartContractEvent(data []byte) (*SmartContactEvent, error) {
	event := &SmartContactEvent{}
	err := json.Unmarshal(data, &event)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return event, nil
}

func GetSmartContractEventLog(data []byte) (*SmartContractEventLog, error) {
	log := &SmartContractEventLog{}
	err := json.Unmarshal(data, &log)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContractEventLog:%s error:%s", data, err)
	}
	return log, nil
}

func GetSmartContactEvents(data []byte) ([]*SmartContactEvent, error) {
	events := make([]*SmartContactEvent, 0)
	err := json.Unmarshal(data, &events)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return events, nil
}

func GetSmartContract(data []byte) (*DeployCode, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	if hexStr == "" {
		return nil, nil
	}
	hexData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	buf := bytes.NewReader(hexData)
	deploy := &DeployCode{}
	err = deploy.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return deploy, nil
}

func GetMerkleProof(data []byte) (*MerkleProof, error) {
	proof := &MerkleProof{}
	err := json.Unmarshal(data, proof)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return proof, nil
}

func GetBlockTxHashes(data []byte) (*BlockTxHashes, error) {
	blockTxHashesStr := &BlockTxHashesStr{}
	err := json.Unmarshal(data, &blockTxHashesStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal")
	}
	blockTxHashes := &BlockTxHashes{}

	blockHash, err := Uint256FromHexString(blockTxHashesStr.Hash)
	if err != nil {
		return nil, err
	}
	txHashes := make([]Uint256, 0, len(blockTxHashesStr.Transactions))
	for _, txHashStr := range blockTxHashesStr.Transactions {
		txHash, err := Uint256FromHexString(txHashStr)
		if err != nil {
			return nil, err
		}
		txHashes = append(txHashes, txHash)
	}
	blockTxHashes.Hash = blockHash
	blockTxHashes.Height = blockTxHashesStr.Height
	blockTxHashes.Transactions = txHashes
	return blockTxHashes, nil
}

func GetMemPoolTxState(data []byte) (*MemPoolTxState, error) {
	txState := &MemPoolTxState{}
	err := json.Unmarshal(data, txState)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return txState, nil
}

func GetMemPoolTxCount(data []byte) (*MemPoolTxCount, error) {
	count := make([]uint32, 0, 2)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	if len(count) != 2 {
		return nil, fmt.Errorf("count len != 2")
	}
	return &MemPoolTxCount{
		Verified: count[0],
		Verifing: count[1],
	}, nil
}
