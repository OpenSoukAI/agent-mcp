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
	"net/url"
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

// cdpHTTPError carries a CDP response's status code, so a caller (selfTest's 401/403 handling,
// a 404 account lookup) can branch on it without parsing the error string.
type cdpHTTPError struct {
	status int
	detail string // "errorType: errorMessage"
}

func (e *cdpHTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.detail) }

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
		httpErr := &cdpHTTPError{status: resp.StatusCode, detail: fmt.Sprintf("%s: %s", e.ErrorType, e.ErrorMessage)}
		return nil, fmt.Errorf("CDP %s %s: %w", method, path, httpErr)
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

const cdpDefaultBase = "https://api.cdp.coinbase.com/platform"

// cdpDeadAddress is the self-test transaction's destination: a well-known burn address, so a
// policy misconfigured enough to let the simulated send through would still be harmless.
var cdpDeadAddress = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// cdpHost is the JWT "uris" claim's host component: the base URL's host plus any path prefix, no
// trailing slash (e.g. "api.cdp.coinbase.com/platform" for the default base).
func cdpHost(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("CDP_API_BASE_URL %q is not a valid URL", base)
	}
	return strings.TrimRight(u.Host+u.Path, "/"), nil
}

// account fetches addr's CDP Server Wallet account and confirms CDP agrees it exists and answers
// for this exact address, so a stale or mistyped AGENT_WALLETS entry fails at boot.
func (c *cdpClient) account(ctx context.Context, addr common.Address) error {
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	out, err := c.do(ctx, http.MethodGet, "/v2/evm/accounts/"+addr.Hex(), nil)
	if err != nil {
		var httpErr *cdpHTTPError
		if errors.As(err, &httpErr) && httpErr.status == http.StatusNotFound {
			return fmt.Errorf("CDP account %s: no CDP account", addr.Hex())
		}
		return err
	}
	got, _ := out["address"].(string)
	if !strings.EqualFold(got, addr.Hex()) {
		return fmt.Errorf("CDP account %s: CDP returned a different address (%s)", addr.Hex(), got)
	}
	return nil
}

// selfTest proves addr's CDP policy is not permissive enough to let the signer bypass it: CDP's
// policy engine must reject signEvmHash, signEvmMessage and signEvmTransaction alike. The signer
// itself never calls the first two (see the package comment) — this additionally checks that the
// project policy would refuse them too, so a gap in the generated template can't be exploited by
// calling CDP directly with the same account.
func (c *cdpClient) selfTest(ctx context.Context, addr common.Address) error {
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &cdpDeadAddress,
		Value:     big.NewInt(1),
	})
	raw, err := unsignedTxRLP(tx, big.NewInt(1))
	if err != nil {
		return fmt.Errorf("CDP account %s: build the self-test transaction: %w", addr.Hex(), err)
	}
	checks := []struct {
		operation string
		body      map[string]any
	}{
		{"signEvmHash", map[string]any{"operation": "signEvmHash", "address": addr.Hex(), "hash": "0x" + strings.Repeat("00", 31) + "01"}},
		{"signEvmMessage", map[string]any{"operation": "signEvmMessage", "address": addr.Hex(), "message": "opensouk self-test"}},
		{"signEvmTransaction", map[string]any{"operation": "signEvmTransaction", "address": addr.Hex(), "transaction": hexutil.Encode(raw)}},
	}
	for _, chk := range checks {
		callCtx, cancel := context.WithTimeout(ctx, providerCallTimeout)
		out, err := c.do(callCtx, http.MethodPost, "/v2/policy-engine/simulate", chk.body)
		cancel()
		if err != nil {
			var httpErr *cdpHTTPError
			if errors.As(err, &httpErr) && (httpErr.status == http.StatusUnauthorized || httpErr.status == http.StatusForbidden) {
				return fmt.Errorf("CDP API key cannot run the policy self-test (HTTP %d: %s); the signer key needs no extra scopes for this — check the key belongs to the project and its IP allowlist", httpErr.status, httpErr.detail)
			}
			return fmt.Errorf("CDP account %s: policy self-test: %w", addr.Hex(), err)
		}
		if action, _ := out["action"].(string); action != "reject" {
			return fmt.Errorf("CDP account %s: the policy accepts %s, so the signer would sign outside the generated policy; apply docs/signer-policies/cdp.%s.json as the account policy and keep the project policy from accepting it (see docs/signer-policies)", addr.Hex(), chk.operation, policyVersion)
		}
	}
	return nil
}

// cdpKeystore opens SIGNER_BACKEND=cdp: AGENT_WALLETS maps agent ids to CDP Server Wallet EVM
// addresses. Each account is checked to exist and to pass the policy self-test before any tool
// can use it, so an unreachable or too-permissive policy fails at boot, not on first use.
func cdpKeystore(ctx context.Context, getenv func(string) string, wallets string) (*keystore, []string, error) {
	vals := map[string]string{}
	for _, k := range []string{"CDP_API_KEY_ID", "CDP_API_KEY_SECRET", "CDP_WALLET_SECRET"} {
		vals[k] = strings.TrimSpace(getenv(k))
		if vals[k] == "" {
			return nil, nil, fmt.Errorf("SIGNER_BACKEND=cdp needs %s", k)
		}
	}
	key, err := cdpAPIKeyFromEnv(vals["CDP_API_KEY_ID"], vals["CDP_API_KEY_SECRET"])
	if err != nil {
		return nil, nil, err
	}
	wallet, err := cdpWalletSecret(vals["CDP_WALLET_SECRET"])
	if err != nil {
		return nil, nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(getenv("CDP_API_BASE_URL")), "/")
	if base == "" {
		base = cdpDefaultBase
	}
	host, err := cdpHost(base)
	if err != nil {
		return nil, nil, err
	}
	c := &cdpClient{base: base, host: host, key: key, wallet: wallet, http: &http.Client{}}

	var report []string
	ks, _, err := walletKeystore(ctx, wallets, "CDP account", func(ctx context.Context, ref string) (Signer, error) {
		if !common.IsHexAddress(ref) {
			return nil, fmt.Errorf("AGENT_WALLETS CDP entry %q is not an EVM address", ref)
		}
		addr := common.HexToAddress(ref)
		if err := c.account(ctx, addr); err != nil {
			return nil, err
		}
		if err := c.selfTest(ctx, addr); err != nil {
			return nil, err
		}
		report = append(report, fmt.Sprintf("CDP account %s (policy self-test passed)", addr.Hex()))
		return &cdpSigner{c: c, addr: addr}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return ks, append(report, fmt.Sprintf("CDP API key %s: make sure it has neither the Export nor the Manage scope (see docs/signer-policies)", key.id)), nil
}
