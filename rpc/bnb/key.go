package bnb

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	cryptoAmino "github.com/tendermint/tendermint/crypto/encoding/amino"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

type KeyManager interface {
	Sign(StdSignMsg) ([]byte, error)
	GetPrivKey() PrivKey
	GetAddr() AccAddress
	GetPublicKey() crypto.PubKey

	// ExportAsMnemonic() (string, error)
	ExportAsPrivateKey() (string, error)
	// ExportAsKeyStore(password string) (*EncryptedKeyJSON, error)
}
type Address = HexBytes

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifyBytes(msg []byte, sig []byte) bool
	Equals(PubKey) bool
}

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) ([]byte, error)
	PubKey() crypto.PubKey
	Equals(crypto.PrivKey) bool
}

// The main purpose of HexBytes is to enable HEX-encoding for json/encoding.
type HexBytes []byte

// Marshal needed for protobuf compatibility
func (bz HexBytes) Marshal() ([]byte, error) {
	return bz, nil
}

// Unmarshal needed for protobuf compatibility
func (bz *HexBytes) Unmarshal(data []byte) error {
	*bz = data
	return nil
}

// This is the point of Bytes.
func (bz HexBytes) MarshalJSON() ([]byte, error) {
	s := strings.ToUpper(hex.EncodeToString(bz))
	jbz := make([]byte, len(s)+2)
	jbz[0] = '"'
	copy(jbz[1:], []byte(s))
	jbz[len(jbz)-1] = '"'
	return jbz, nil
}

// This is the point of Bytes.
func (bz *HexBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("Invalid hex string: %s", data)
	}
	bz2, err := hex.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*bz = bz2
	return nil
}

// Allow it to fulfill various interfaces in light-client, etc...
func (bz HexBytes) Bytes() []byte {
	return bz
}

func (bz HexBytes) String() string {
	return strings.ToUpper(hex.EncodeToString(bz))
}

func (bz HexBytes) Format(s fmt.State, verb rune) {
	switch verb {
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", bz)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(bz))))
	}
}

type EncryptedKeyJSON struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}
type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type keyManager struct {
	privKey  PrivKey
	addr     AccAddress
	mnemonic string
}

type Tx interface {

	// Gets the Msg.
	GetMsgs() []Msg
}

var Cdc = amino.NewCodec()

// RegisterCodec .
func RegisterCodec(cdc *amino.Codec) {
	cdc.RegisterInterface((*Tx)(nil), nil)
	cdc.RegisterInterface((*Msg)(nil), nil)
	cdc.RegisterConcrete(StdTx{}, "auth/StdTx", nil)
	cdc.RegisterConcrete(SendMsg{}, "cosmos-sdk/Send", nil)
}

func init() {
	cryptoAmino.RegisterAmino(Cdc)
	RegisterCodec(Cdc)
}

func (m *keyManager) ExportAsPrivateKey() (string, error) {
	secpPrivateKey, ok := m.privKey.(secp256k1.PrivKeySecp256k1)
	if !ok {
		return "", fmt.Errorf(" Only PrivKeySecp256k1 key is supported ")
	}
	return hex.EncodeToString(secpPrivateKey[:]), nil
}

func (m *keyManager) Sign(msg StdSignMsg) ([]byte, error) {
	sig, err := m.makeSignature(msg)
	if err != nil {
		return nil, err
	}
	newTx := NewStdTx(msg.Msgs, []StdSignature{sig}, msg.Memo, msg.Source, msg.Data)

	bz, err := Cdc.MarshalBinaryLengthPrefixed(&newTx)
	if err != nil {
		return nil, err
	}

	//return bz, nil
	return []byte(hex.EncodeToString(bz)), nil
}

func (m *keyManager) GetPrivKey() PrivKey {
	return m.privKey
}

func (m *keyManager) GetAddr() AccAddress {
	return m.addr
}
func (m *keyManager) GetPublicKey() crypto.PubKey {
	return m.privKey.PubKey()
}
func (m *keyManager) makeSignature(msg StdSignMsg) (sig StdSignature, err error) {
	if err != nil {
		return
	}
	sigBytes, err := m.privKey.Sign(msg.Bytes())
	if err != nil {
		return
	}

	return StdSignature{
		AccountNumber: msg.AccountNumber,
		Sequence:      msg.Sequence,
		PubKey:        m.privKey.PubKey(),
		Signature:     sigBytes,
	}, nil
}

func NewPrivateKeyManager(priKey string) (KeyManager, error) {
	k := keyManager{}
	err := k.recoveryFromPrivateKey(priKey)
	return &k, err
}

func (m *keyManager) recoveryFromPrivateKey(privateKey string) error {
	priBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return err
	}

	if len(priBytes) != 32 {

		return fmt.Errorf("Len of Keybytes is not equal to 32 ")
	}
	var keyBytesArray [32]byte
	copy(keyBytesArray[:], priBytes[:32])
	priKey := secp256k1.PrivKeySecp256k1(keyBytesArray)
	addr := AccAddress(priKey.PubKey().Address())
	m.addr = addr
	m.privKey = priKey
	return nil
}
