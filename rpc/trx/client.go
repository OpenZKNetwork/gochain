package trx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/go-resty/resty"
)

// TransactionReceipt .
type TransactionReceipt struct {
	Ret        []RetInfo `json:"ret"`
	Signature  []string  `json:"signature"`
	TxID       string    `json:"txID"`
	RawDataHex string    `json:"raw_data_hex"`
	RawData    RawData   `json:"raw_data"`
}

// CreateTransactionResponse .
type CreateTransactionResponse struct {
	Visible    bool     `json:"visible"`
	TxID       string   `json:"txID"`
	RawData    RawData  `json:"raw_data"`
	RawDataHex string   `json:"raw_data_hex"`
	Signature  []string `json:"signature"`
}

// RetInfo .
type RetInfo struct {
	ContractRet string `json:"contractRet"`
}

// RawData .
type RawData struct {
	Contract      []RawDataContractInfo `json:"contract"`
	RefBlockBytes string                `json:"ref_block_bytes"`
	RefBlockHash  string                `json:"ref_block_hash"`
	Expiration    uint64                `json:"expiration"`
	Timestamp     uint64                `json:"timestamp"`
}

// RawDataContractInfo .
type RawDataContractInfo struct {
	Parameter Parameter `json:"parameter"`
	Type      string    `json:"type"`
}

// Parameter .
type Parameter struct {
	Value   ParameterValue `json:"value"`
	TypeURL string         `json:"type_url"`
}

// ParameterValue .
type ParameterValue struct {
	OwnerAddress    string `json:"owner_address"`
	Amount          uint64 `json:"amount"`           //transaction receipt interface 含有
	AssetName       string `json:"asset_name"`       //transaction receipt interface 含有
	ToAddress       string `json:"to_address"`       //transaction receipt interface 含有
	Data            string `json:"data"`             //block interface 含有
	ContractAddress string `json:"contract_address"` //block interface 含有
}

// Transaction .
type Transaction struct {
	ParameterValue
	TxID   string `json:"tx_id"`
	State  string `json:"state"`
	TxType string `json:"tx_type"`
}

// Block .
type Block struct {
	BlockID      string               `json:"blockID"`
	BlockHeader  BlockHeader          `json:"block_header"`
	Transactions []TransactionReceipt `json:"transactions"`
}

// BlockHeader .
type BlockHeader struct {
	RawData          BlockRawData `json:"raw_data"`
	WitnessSignature string       `json:"witness_signature"`
}

// BlockRawData .
type BlockRawData struct {
	Number         int64  `json:"number"`
	TxTrieRoot     string `json:"txTrieRoot"`
	WitnessAddress string `json:"witness_address"`
	ParentHash     string `json:"parentHash"`
	Version        uint   `json:"version"`
	Timestamp      uint64 `json:"timestamp"`
}

// Account .
type Account struct {
	AccountName string         `json:"account_name"`
	Address     string         `json:"address"`
	Balance     uint64         `json:"balance"`
	Asset       []AccountAsset `json:"asset"`
}

// AccountAsset .
type AccountAsset struct {
	Key   string `json:"key"`
	Value uint64 `json:"value"`
}

// Fee .
type Fee struct {
	TxID           string `json:"id"`
	Fee            uint64 `json:"fee"`
	BlockNumber    uint64 `json:"blockNumber"`
	BlockTimeStamp uint64 `json:"blockTimeStamp"`
}

//Client .
type Client interface {
	GetAccount(address string) (*Account, error)
	GetBalance(addr string, symbol string) (uint64, error)
	CreateTransaction(from, to string, amount uint32) (*CreateTransactionResponse, error)
	// Transfer(keyManager KeyManager, transfers []Transfer) (*TxCommitResult, error)
	// GetTokens() ([]Token, error)
	GetTransactionReceipt(txid string) (*TransactionReceipt, error)
	GetTransactionFee(txid string) (*Fee, error)
	GetBlockByNumber(height uint32) (*Block, error)
	BestBlockNumber() (uint32, error)
	SendRawTransaction(tx []byte) (string, error)
}
type client struct {
	apiURL string
}

// New .
func New(apiURL string) Client {
	client := &client{apiURL: apiURL}
	return client
}

func (c *client) SendRawTransaction(tx []byte) (string, error) {
	body, err := c.Post("/wallet/broadcasttransaction", tx, nil)
	if err != nil {
		return "", err
	}

	var parse map[string]interface{}
	if err := json.Unmarshal(body, &parse); err != nil {
		return "", err
	}
	if _, ok := parse["result"].(bool); ok {
		transaction := new(CreateTransactionResponse)
		if err := json.Unmarshal(tx, transaction); err != nil {
			return "", err
		}
		return transaction.TxID, nil
	}

	return "", errors.New("transaction error")
}

func (c *client) GetAccount(address string) (*Account, error) {
	hexAddress := Address2Hex(address)
	body, err := c.Post("/wallet/getaccount", map[string]interface{}{"address": hexAddress}, nil)
	if err != nil {
		return nil, err
	}

	var parse *Account
	if err := json.Unmarshal(body, &parse); err != nil {
		return nil, err
	}

	return parse, nil
}

func (c *client) GetBalance(addr string, symbol string) (uint64, error) {
	hexAddress := Address2Hex(addr)
	body, err := c.Post("/wallet/getaccount", map[string]interface{}{"address": hexAddress}, nil)
	if err != nil {
		return 0, err
	}

	var parse *Account
	if err := json.Unmarshal(body, &parse); err != nil {
		return 0, err
	}
	if parse.Asset != nil && len(parse.Asset) > 0 {
		for _, asset := range parse.Asset {
			if asset.Key == symbol {
				return asset.Value, nil
			}
		}
		return 0, nil
	}
	if symbol == "TRX" {
		return parse.Balance, nil
	}
	return 0, nil
}

// CreateTransaction .
func (c *client) CreateTransaction(from, to string, amount uint32) (*CreateTransactionResponse, error) {
	from = Address2Hex(from)
	to = Address2Hex(to)
	body, err := c.Post("/wallet/createtransaction", map[string]interface{}{"to_address": to, "owner_address": from, "amount": amount}, nil)
	if err != nil {
		return nil, err
	}
	var parse *CreateTransactionResponse
	if err := json.Unmarshal(body, &parse); err != nil {
		return nil, err
	}
	return parse, nil
}

func (c *client) GetTransactionReceipt(tx string) (*TransactionReceipt, error) {
	body, err := c.Post("/wallet/gettransactionbyid", map[string]interface{}{"value": tx}, nil)
	if err != nil {
		return nil, err
	}

	var parse *TransactionReceipt
	if err := json.Unmarshal(body, &parse); err != nil {
		return nil, err
	}

	return parse, nil
}

func (c *client) GetTransactionFee(tx string) (*Fee, error) {
	body, err := c.Post("/wallet/gettransactioninfobyid", map[string]interface{}{"value": tx}, nil)
	if err != nil {
		return nil, err
	}

	var parse *Fee
	if err := json.Unmarshal(body, &parse); err != nil {
		return nil, err
	}

	return parse, nil
}

func (c *client) GetBlockByNumber(height uint32) (*Block, error) {
	body, err := c.Post("/wallet/getblockbynum", map[string]interface{}{"num": height}, nil)
	if err != nil {
		return nil, err
	}

	var parse *Block
	if err := json.Unmarshal(body, &parse); err != nil {
		return nil, err
	}

	return parse, nil
}

func (c *client) BestBlockNumber() (uint32, error) {
	body, err := c.Post("/wallet/getnowblock", map[string]interface{}{}, nil)
	if err != nil {
		return 0, err
	}

	var parse *Block
	if err := json.Unmarshal(body, &parse); err != nil {
		return 0, err
	}

	return uint32(parse.BlockHeader.RawData.Number), nil
}

// Post generic method
func (c *client) Post(path string, body interface{}, param map[string]string) ([]byte, error) {
	body, ok := body.(map[string]interface{})
	if ok {
		var err error
		body, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	resp, err := resty.R().
		SetHeader("Content-Type", "text/plain").
		SetBody(body).
		SetQueryParams(param).
		Post(c.apiURL + path)

	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= http.StatusMultipleChoices {
		err = fmt.Errorf("bad response, status code %d, response: %s", resp.StatusCode(), string(resp.Body()))
	}
	return resp.Body(), err
}

// Address2Hex .
func Address2Hex(address string) string {
	if len(address) == 42 && strings.HasPrefix(address, "41") {
		return address
	}

	b := base58.Decode(address)
	return strings.ToUpper(hex.EncodeToString(b[:len(b)-4]))
}

// Hex2Address .
func Hex2Address(hexStr string) (string, error) {
	if !strings.HasPrefix(hexStr, "41") {
		return hexStr, nil
	}
	var addressCheck []byte
	address, err := hex.DecodeString(hexStr)

	if err != nil {
		return "", err
	}
	sha := sha256.New()
	sha.Write(address)
	h1 := sha.Sum(nil)
	sha2 := sha256.New()
	sha2.Write(h1)
	h2 := sha2.Sum(nil)

	addressCheck = append(addressCheck, address...)
	addressCheck = append(addressCheck, h2[0:4]...)
	return base58.Encode(addressCheck), nil
}
