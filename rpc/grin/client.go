package grin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-resty/resty"
)

const (
	// GrinAPIVersion .
	GrinAPIVersion = "/v1"
)

// BestBlockNumber .
type BestBlockNumber struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Height  uint32 `json:"height"`
}

//Client .
type Client interface {
	// GetAccount(address string) (*Account, error)
	// GetBalance(addr string, symbol string) (uint64, error)
	// CreateTransaction(from, to string, amount uint32) (*CreateTransactionResponse, error)
	// Transfer(keyManager KeyManager, transfers []Transfer) (*TxCommitResult, error)
	// GetTokens() ([]Token, error)
	// GetTransactionReceipt(txid string) (*TransactionReceipt, error)
	// GetTransactionFee(txid string) (*Fee, error)
	// GetBlockByNumber(height uint32) (*Block, error)
	BestBlockNumber() (uint32, error)
	// SendRawTransaction(tx []byte) (string, error)
}
type client struct {
	apiURL string //testnet https://floonet-api.grinmint.com
}

// New .
func New(apiURL string) Client {
	client := &client{apiURL: apiURL}
	return client
}

func (c *client) BestBlockNumber() (uint32, error) {
	body, err := c.Post("/networkStats", map[string]interface{}{}, nil)
	if err != nil {
		return 0, err
	}

	var parse *BestBlockNumber
	if err := json.Unmarshal(body, &parse); err != nil {
		return 0, err
	}

	if !parse.Status {
		return 0, errors.New(parse.Message)
	}
	return parse.Height, nil
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
		Post(c.apiURL + GrinAPIVersion + path)

	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= http.StatusMultipleChoices {
		err = fmt.Errorf("bad response, status code %d, response: %s", resp.StatusCode(), string(resp.Body()))
	}
	return resp.Body(), err
}
