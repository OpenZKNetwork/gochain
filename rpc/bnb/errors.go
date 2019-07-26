package bnb

import (
	"errors"
	"fmt"
)

var (
	// Param error
	AddressMissingError           = errors.New("Address is required ")
	SymbolMissingError            = errors.New("Symbol is required ")
	OffsetOutOfRangeError         = errors.New("offset out of range ")
	LimitOutOfRangeError          = errors.New("limit out of range ")
	TradeSideMisMatchError        = errors.New("Trade side is invalid ")
	StartTimeOutOfRangeError      = errors.New("start time out of range ")
	EndTimeOutOfRangeError        = errors.New("end time out of range ")
	IntervalMissingError          = errors.New("interval is required ")
	EndTimeLessThanStartTimeError = errors.New("end time should great than start time")
	OrderIdMissingError           = errors.New("order id is required ")

	ExceedABCIPathLengthError         = fmt.Errorf("the abci path exceed max length %d ", maxABCIPathLength)
	ExceedABCIDataLengthError         = fmt.Errorf("the abci data exceed max length %d ", maxABCIDataLength)
	ExceedTxLengthError               = fmt.Errorf("the tx data exceed max length %d ", maxTxLength)
	LimitNegativeError                = fmt.Errorf("the limit can't be negative")
	ExceedMaxUnConfirmedTxsNumError   = fmt.Errorf("the limit of unConfirmed tx exceed max limit %d ", maxUnConfirmedTxs)
	HeightNegativeError               = fmt.Errorf("the height can't be negative")
	MaxMinHeightConflictError         = fmt.Errorf("the min height can't be larger than max height")
	HashLengthError                   = fmt.Errorf("the length of hash is not 32")
	ExceedABCIQueryStrLengthError     = fmt.Errorf("the query string exceed max length %d ", maxABCIPathLength)
	ExceedTxSearchQueryStrLengthError = fmt.Errorf("the query string exceed max length %d ", maxTxSearchStrLength)
	OffsetNegativeError               = fmt.Errorf("offset can't be less than 0")
	SymbolLengthExceedRangeError      = fmt.Errorf("length of symbol should be in range [%d,%d]", tokenSymbolMinLen, tokenSymbolMaxLen)
	PairFormatError                   = fmt.Errorf("the pair should in format 'symbol1_symbol2'")
)
