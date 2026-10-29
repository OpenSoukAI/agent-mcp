package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// CDP backend (SIGNER_BACKEND=cdp). The wallet key stays in a Coinbase CDP Server Wallet and every
// request is authenticated two ways: the bearer JWT (cdpAPIKey) identifies the API caller, and for
// any write under /accounts the wallet JWT (p256Credential) binds the request to its exact body via
// reqHash, which is what CDP's policy engine evaluates. Typed data is sent as domain/types/
// primaryType/message so the policy sees the structure; transactions go as the unsigned RLP CDP
// parses and signs itself. Raw hashes and personal messages are never sent: CDP's only raw-hash
// endpoint (sign/hash) is unrestrictable by policy.

// cdpClient talks to one CDP Server Wallet project. host is the base URL's host plus any path
// prefix (e.g. "api.cdp.coinbase.com/platform"), which the JWTs' uris claim is built from.
type cdpClient struct {
	base, host string
	key        *cdpAPIKey
	wallet     *p256Credential
	http       *http.Client
}

// do sends one CDP request, body (nil for none) encoded with cdpBody so the bytes signed by the
// wallet JWT are exactly the bytes sent. The bearer JWT authenticates every request; the wallet
// JWT additionally authorizes a write under /accounts, the only paths CDP's policy engine covers.
func (c *cdpClient) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var raw []byte
	if body != nil {
		var err error
		raw, err = cdpBody(body)
		if err != nil {
			return nil, err
		}
	}
	uri := method + " " + c.host + path
	now := time.Now()
	bearer, err := c.key.bearer(uri, now)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if raw != nil {
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	isWrite := method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete
	if isWrite && strings.Contains(path, "/accounts") {
		walletJWT, err := c.wallet.cdpWalletJWT(uri, raw, now)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Wallet-Auth", walletJWT)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CDP %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			ErrorType    string `json:"errorType"`
			ErrorMessage string `json:"errorMessage"`
		}
		_ = json.Unmarshal(respRaw, &e)
		return nil, fmt.Errorf("CDP %s %s: HTTP %d: %s: %s", method, path, resp.StatusCode, e.ErrorType, e.ErrorMessage)
	}
	var out map[string]any
	if err := json.Unmarshal(respRaw, &out); err != nil {
		return nil, fmt.Errorf("CDP %s %s: decode response: %w", method, path, err)
	}
	return out, nil
}

type cdpSigner struct {
	c    *cdpClient
	addr common.Address
}

func (s *cdpSigner) Address() common.Address { return s.addr }

func (s *cdpSigner) SignDigest(context.Context, [32]byte) ([]byte, error) {
	return nil, errRawDigestRefused
}

func (s *cdpSigner) SignPersonalMessage(context.Context, []byte) ([]byte, error) {
	return nil, s.agentAuthRefusal()
}

func (s *cdpSigner) agentAuthRefusal() error {
	return errors.New("SIGNER_BACKEND=cdp cannot personal-sign: CDP signs text only, and the agent-auth message is 32 raw bytes, which only CDP's unrestrictable sign-hash endpoint takes. The merchant REST tools need it; run them with SIGNER_BACKEND=privy, kms or local")
}

func (s *cdpSigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	payload, err := providerTypedDataJSON(td, "primaryType", false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	out, err := s.c.do(ctx, http.MethodPost, "/v2/evm/accounts/"+s.addr.Hex()+"/sign/typed-data", payload)
	if err != nil {
		return nil, err
	}
	sigHex, _ := out["signature"].(string)
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		return nil, fmt.Errorf("CDP signature: %w", err)
	}
	return checkSig65(sig, [32]byte(hash), s.addr)
}

func (s *cdpSigner) SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx.Type() != types.DynamicFeeTxType {
		return nil, fmt.Errorf("transaction type %d is not supported by remote signing", tx.Type())
	}
	if tx.To() == nil {
		return nil, errors.New("CDP signing does not cover contract creation")
	}
	raw, err := unsignedTxRLP(tx, chainID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	out, err := s.c.do(ctx, http.MethodPost, "/v2/evm/accounts/"+s.addr.Hex()+"/sign/transaction", map[string]any{
		"transaction": hexutil.Encode(raw),
	})
	if err != nil {
		return nil, err
	}
	signedHex, _ := out["signedTransaction"].(string)
	signed, err := hexutil.Decode(signedHex)
	if err != nil || len(signed) == 0 {
		return nil, errors.New("CDP returned no signed transaction")
	}
	return attachProviderSig(signed, tx, chainID, s.addr)
}
