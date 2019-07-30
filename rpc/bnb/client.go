package bnb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	ctypes "github.com/tendermint/tendermint/rpc/core/types"

	"github.com/go-resty/resty"
)

//Client .
type Client interface {
	Get(string, map[string]string, bool) ([]byte, int, error)
	GetAccount(address string) (*BalanceAccount, error)
	GetBalance(addr string, symbol string) (*TokenBalance, error)
	Transfer(keyManager KeyManager, transfers []Transfer) (*TxCommitResult, error)
	GetTokens() ([]Token, error)
	GetTransactionReceipt(tx string) (*TxResponse, error)
	GetBlockByNumber(height uint32) (*ctypes.ResultBlock, error)
	BestBlockNumber() (uint32, error)
	SendRawTransaction(tx []byte) (string, error)
}
type client struct {
	baseURL string
	apiURL  string
	chainID string
	wsURL   string
}

// New .
func New(HTTPURL, WsURL string, network int) Client {
	client := &client{baseURL: HTTPURL, apiURL: fmt.Sprintf("%s://%s", DefaultApiSchema, HTTPURL+DefaultAPIVersionPrefix), wsURL: WsURL}
	res, err := client.GetNodeInfo()
	if err != nil {
		panic(err)
	}
	client.chainID = res.NodeInfo.Network
	Network = ChainNetwork(network)
	// client.chainID = "Binance-Chain-Nile"
	return client

}

func (c *client) GetNodeInfo() (*ResultStatus, error) {
	qp := map[string]string{}
	resp, _, err := c.Get("/node-info", qp, false)
	if err != nil {
		return nil, err
	}

	var resultStatus ResultStatus
	if err := json.Unmarshal(resp, &resultStatus); err != nil {
		return nil, err
	}

	return &resultStatus, nil
}
func (c *client) BestBlockNumber() (uint32, error) {
	res, err := c.GetNodeInfo()
	if err != nil {
		return 0, err
	}
	return res.SyncInfo.Height, nil
}

// // CreateOrder 同一账户中,币种转换
// func (c *client) CreateOrder(keyManager KeyManager, baseAssetSymbol, quoteAssetSymbol string, op int8, price, quantity int64) (*CreateOrderResult, error) {
// 	if baseAssetSymbol == "" || quoteAssetSymbol == "" {
// 		return nil, fmt.Errorf("BaseAssetSymbol or QuoteAssetSymbol is missing. ")
// 	}
// 	fromAddr := keyManager.GetAddr()

// 	newOrderMsg := CreateOrderMsg{
// 		Sender:      fromAddr,
// 		ID:          "",
// 		Symbol:      CombineSymbol(baseAssetSymbol, quoteAssetSymbol),
// 		OrderType:   OrderType.LIMIT, // default
// 		Side:        op,
// 		Price:       price,
// 		Quantity:    quantity,
// 		TimeInForce: TimeInForce.GTC, // default
// 	}
// 	commit, err := c.broadcastMsg(keyManager, newOrderMsg,true)
// 	if err != nil {
// 		return nil, err
// 	}
// 	type commitData struct {
// 		OrderID string `json:"order_id"`
// 	}
// 	var cdata commitData
// 	err = json.Unmarshal([]byte(commit.Data), &cdata)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &CreateOrderResult{*commit, cdata.OrderID}, nil
// }

func (c *client) Transfer(keyManager KeyManager, transfers []Transfer) (*TxCommitResult, error) {
	fromAddr := keyManager.GetAddr()
	fromCoins := Coins{}
	for _, t := range transfers {
		t.Coins = t.Coins.Sort()
		fromCoins = fromCoins.Plus(t.Coins)
	}
	sendMsg := CreateSendMsg(fromAddr, fromCoins, transfers)
	commit, err := c.broadcastMsg(keyManager, sendMsg, true)
	if err != nil {

		return nil, err
	}
	return commit, err

}

func (c *client) SendRawTransaction(tx []byte) (string, error) {
	param := map[string]string{"sync": "true"}
	commits, err := c.PostTx(tx, param)
	if err != nil {
		return "", err
	}
	if len(commits) < 1 {
		return "", fmt.Errorf("Len of tx Commit result is less than 1 ")
	}
	return *(&commits[0].Hash), nil
}

func (c *client) broadcastMsg(keyManager KeyManager, m Msg, sync bool) (*TxCommitResult, error) {
	// prepare message to sign
	signMsg := &StdSignMsg{
		ChainID: c.chainID,
		Memo:    "",
		Msgs:    []Msg{m},
		Source:  Source,
	}
	fromAddr := keyManager.GetAddr()
	acc, err := c.GetAccount(fromAddr.String())
	if err != nil {
		return nil, err
	}
	signMsg.Sequence = acc.Sequence
	signMsg.AccountNumber = acc.Number

	// // special logic for createOrder, to save account query
	// if orderMsg, ok := m.(CreateOrderMsg); ok {
	// 	orderMsg.ID = GenerateOrderID(signMsg.Sequence+1, keyManager.GetAddr())
	// 	signMsg.Msgs[0] = orderMsg
	// }

	for _, m := range signMsg.Msgs {
		if err := m.ValidateBasic(); err != nil {
			return nil, err
		}
	}

	// Hex encoded signed transaction, ready to be posted to BncChain API
	hexTx, err := keyManager.Sign(*signMsg)
	if err != nil {
		return nil, err
	}

	param := map[string]string{}
	if sync {
		param["sync"] = "true"
	}
	commits, err := c.PostTx(hexTx, param)
	if err != nil {
		return nil, err
	}
	if len(commits) < 1 {
		return nil, fmt.Errorf("Len of tx Commit result is less than 1 ")
	}
	return &commits[0], nil
}

// GetAccount returns list of trading pairs
func (c *client) GetAccount(address string) (*BalanceAccount, error) {
	if address == "" {
		return nil, AddressMissingError
	}

	qp := map[string]string{}
	resp, code, err := c.Get("/account/"+address, qp, false)
	if err != nil {
		if code == http.StatusNotFound {
			return &BalanceAccount{}, nil
		}
		return nil, err
	}
	var account BalanceAccount
	if err := json.Unmarshal(resp, &account); err != nil {
		return nil, err
	}
	account.ChainID = c.chainID
	return &account, nil
}

// GetTransactionReceipt returns transaction detail
func (c *client) GetTransactionReceipt(tx string) (*TxResponse, error) {
	if tx == "" {
		return nil, OrderIdMissingError
	}

	resp, code, err := c.Get("/tx/"+tx, map[string]string{"format": "json"}, false)
	if err != nil {
		if code == http.StatusNotFound {
			return &TxResponse{}, nil
		}
		return nil, err
	}

	res := new(TxResponse)
	if err := json.Unmarshal(resp, res); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return res, nil
}

func (c *client) GetBalance(addr string, symbol string) (*TokenBalance, error) {
	if err := ValidateSymbol(symbol); err != nil {
		return nil, err
	}
	acc, err := c.GetAccount(addr)
	if err != nil {
		return nil, err
	}
	symbol = strings.ToLower(symbol)
	balance := &TokenBalance{
		Symbol: symbol,
		Free:   Fixed8(0),
		Locked: Fixed8(0),
		Frozen: Fixed8(0),
	}
	for _, v := range acc.Balances {
		if strings.ToLower(v.Symbol) == symbol {
			balance = &TokenBalance{
				Symbol: symbol,
				Free:   Fixed8(v.Free),
				Locked: Fixed8(v.Locked),
				Frozen: Fixed8(v.Frozen),
			}
		}
	}
	return balance, nil
}

// Post generic method
func (c *client) Post(path string, body interface{}, param map[string]string) ([]byte, error) {
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

// PostTx returns transaction details
func (c *client) PostTx(hexTx []byte, param map[string]string) ([]TxCommitResult, error) {
	if len(hexTx) == 0 {
		return nil, fmt.Errorf("Invalid tx  %s", hexTx)
	}

	body := hexTx
	resp, err := c.Post("/broadcast", body, param)
	if err != nil {
		return nil, err
	}
	txResult := make([]TxCommitResult, 0)
	if err := json.Unmarshal(resp, &txResult); err != nil {
		return nil, err
	}

	return txResult, nil
}

func (c *client) GetBlockByNumber(height uint32) (*ctypes.ResultBlock, error) {
	block, _, err := c.Get("/block", map[string]string{"height": fmt.Sprintf("%d", height)}, true)
	if err != nil {
		return nil, err
	}
	res := new(ctypes.ResultBlock)
	err = json.Unmarshal(block, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetTokens returns list of tokens
func (c *client) GetTokens() ([]Token, error) {
	qp := map[string]string{}
	resp, _, err := c.Get("/tokens", qp, false)
	if err != nil {
		return nil, err
	}

	var tokens []Token
	if err := json.Unmarshal(resp, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

func (c *client) Get(path string, qp map[string]string, isWs bool) ([]byte, int, error) {
	url := c.apiURL
	if isWs {
		url = c.wsURL
	}
	resp, err := resty.R().SetQueryParams(qp).Get(url + path)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode() >= http.StatusMultipleChoices || resp.StatusCode() < http.StatusOK {
		err = fmt.Errorf("bad response, status code %d, response: %s", resp.StatusCode(), string(resp.Body()))
	}
	return resp.Body(), resp.StatusCode(), err
}

// GenerateOrderID generates an order ID
func GenerateOrderID(sequence int64, from AccAddress) string {
	id := fmt.Sprintf("%X-%d", from.Bytes(), sequence)
	return id
}

// CombineSymbol .
func CombineSymbol(baseAssetSymbol, quoteAssetSymbol string) string {
	return fmt.Sprintf("%s_%s", baseAssetSymbol, quoteAssetSymbol)
}
