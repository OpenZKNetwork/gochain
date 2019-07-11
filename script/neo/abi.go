package neo

import (
	"encoding/hex"
	"errors"

	"github.com/openzknetwork/gochain/rpc/ont"
)

//ParseNotifyActionName 解析event notify 操作类型
func ParseNotifyActionName(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

//ParseNotifyAddress 解析event notify address
func ParseNotifyAddress(s string) (string, error) {
	b := []byte(s)
	if len(b) != 40 {
		return "", errors.New("address len is not eq 40")
	}
	addr, err := ont.AddressFromHexString(string(ont.AddressByteArrayReverse(b)))
	if err != nil {
		return "", err
	}
	return addr.ToBase58(), nil
}
