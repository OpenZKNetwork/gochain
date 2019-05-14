package eos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/dynamicgo/xerrors/apierr"

	"github.com/dynamicgo/xerrors"

	"github.com/dynamicgo/slf4go"
)

// Errors .
var (
	ErrUnknown = apierr.WithScope(-1, "unknown error", "eos-api")
)

type m map[string]interface{}

func enc(v interface{}) (io.Reader, error) {
	if v == nil {
		return nil, nil
	}

	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}

	return buffer, nil
}

// Client .
type Client interface {
	GetAccount(name string) (*Account, error)
}

type clientImpl struct {
	slf4go.Logger
	httpClient *http.Client
	baseURL    string
	header     http.Header
	debug      bool
}

// Option .
type Option func(impl *clientImpl)

// WithDebug .
func WithDebug() Option {
	return func(impl *clientImpl) {
		impl.debug = true
	}
}

// New .
func New(url string, options ...Option) Client {
	client := &clientImpl{
		Logger:     slf4go.Get("eos-rpc"),
		httpClient: http.DefaultClient,
		baseURL:    url,
		header:     make(http.Header),
	}

	for _, option := range options {
		option(client)
	}

	return client
}

func (client *clientImpl) call(baseAPI, name string, params interface{}, returns interface{}) error {
	jsonBody, err := enc(params)

	if err != nil {
		return err
	}

	targetURL := fmt.Sprintf("%s/v1/%s/%s", client.baseURL, baseAPI, name)
	req, err := http.NewRequest("POST", targetURL, jsonBody)

	if err != nil {
		return fmt.Errorf("NewRequest: %s", err)
	}

	for k, v := range client.header {
		if req.Header == nil {
			req.Header = http.Header{}
		}
		req.Header[k] = append(req.Header[k], v...)
	}

	if client.debug {
		// Useful when debugging API calls
		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}
		client.DebugF("=========================")
		client.DebugF("%s\n", string(requestDump))
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return xerrors.Wrapf(err, "http dial %s error", req.URL.String())
	}
	defer resp.Body.Close()

	var cnt bytes.Buffer
	_, err = io.Copy(&cnt, resp.Body)
	if err != nil {
		return fmt.Errorf("Copy: %s", err)
	}

	if resp.StatusCode == 404 {
		var apiErr APIError
		if err := json.Unmarshal(cnt.Bytes(), &apiErr); err != nil {
			return err
		}

		return xerrors.Wrapf(apiErr, "eos response error")
	}

	if resp.StatusCode > 299 {
		var apiErr APIError
		if err := json.Unmarshal(cnt.Bytes(), &apiErr); err != nil {
			return fmt.Errorf("%s: status code=%d, body=%s", req.URL.String(), resp.StatusCode, cnt.String())
		}

		// Handle cases where some API calls (/v1/chain/get_account for example) returns a 500
		// error when retrieving data that does not exist.
		if apiErr.IsUnknownKeyError() {
			return xerrors.Wrapf(ErrUnknown, "unknown error from resp: %s", apiErr)
		}

		return xerrors.Wrapf(apiErr, "eos response error")
	}

	if client.debug {
		client.Debug("RESPONSE:")
		responseDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			client.Error(err)
		}
		client.Debug("-------------------------------")
		client.Debug(cnt.String())
		client.Debug("-------------------------------")
		client.DebugF("%q\n", responseDump)
		client.Debug("")
	}

	if err := json.Unmarshal(cnt.Bytes(), &returns); err != nil {
		return xerrors.Wrapf(err, "unmarshal data error: %s", cnt.String())
	}

	return nil
}

func (client *clientImpl) GetAccount(name string) (account *Account, err error) {

	err = client.call("chain", "get_account", m{"account_name": name}, &account)

	return
}
