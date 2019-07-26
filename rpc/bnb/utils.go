package bnb

import "encoding/json"

func ValidateSymbol(symbol string) error {
	if len(symbol) > tokenSymbolMaxLen || len(symbol) < tokenSymbolMinLen {
		return SymbolLengthExceedRangeError
	}
	return nil
}

func CreateSendMsg(from AccAddress, fromCoins Coins, transfers []Transfer) SendMsg {
	input := NewInput(from, fromCoins)

	output := make([]Output, 0, len(transfers))
	for _, t := range transfers {
		t.Coins = t.Coins.Sort()
		output = append(output, NewOutput(t.ToAddr, t.Coins))
	}
	msg := NewMsgSend([]Input{input}, output)
	return msg
}
func NewInput(addr AccAddress, coins Coins) Input {
	input := Input{
		Address: addr,
		Coins:   coins,
	}
	return input
}

// SortJSON takes any JSON and returns it sorted by keys. Also, all white-spaces
// are removed.
// This method can be used to canonicalize JSON to be returned by GetSignBytes,
// e.g. for the ledger integration.
// If the passed JSON isn't valid it will return an error.
func SortJSON(toSortJSON []byte) ([]byte, error) {
	var c interface{}
	err := json.Unmarshal(toSortJSON, &c)
	if err != nil {
		return nil, err
	}
	js, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return js, nil
}

// MustSortJSON is like SortJSON but panic if an error occurs, e.g., if
// the passed JSON isn't valid.
func MustSortJSON(toSortJSON []byte) []byte {
	js, err := SortJSON(toSortJSON)
	if err != nil {
		panic(err)
	}
	return js
}
