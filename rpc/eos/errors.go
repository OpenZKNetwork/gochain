package eos

import (
	"fmt"
	"strings"
)

// APIError represents the errors as reported by the server
type APIError struct {
	Code        int    `json:"code"` // http code
	Message     string `json:"message"`
	ErrorStruct struct {
		Code    int              `json:"code"` // https://docs.google.com/spreadsheets/d/1uHeNDLnCVygqYK-V01CFANuxUwgRkNkrmeLm9MLqu9c/edit#gid=0
		Name    string           `json:"name"`
		What    string           `json:"what"`
		Details []APIErrorDetail `json:"details"`
	} `json:"error"`
}

// APIErrorDetail .
type APIErrorDetail struct {
	Message    string `json:"message"`
	File       string `json:"file"`
	LineNumber int    `json:"line_number"`
	Method     string `json:"method"`
}

func (e APIError) Error() string {
	msg := e.Message
	msg = fmt.Sprintf("%s: %s", msg, e.ErrorStruct.What)

	for _, detail := range e.ErrorStruct.Details {
		msg = fmt.Sprintf("%s: %s", msg, detail.Message)
	}

	return msg
}

// IsUnknownKeyError .
func (e APIError) IsUnknownKeyError() bool {
	return e.Code == 500 &&
		e.ErrorStruct.Code == 0 &&
		e.hasDetailMessagePrefix("unknown key")
}

// hasDetailMessagePrefix .
func (e APIError) hasDetailMessagePrefix(prefix string) bool {
	for _, detail := range e.ErrorStruct.Details {
		if strings.HasPrefix(detail.Message, prefix) {
			return true
		}
	}

	return false
}
