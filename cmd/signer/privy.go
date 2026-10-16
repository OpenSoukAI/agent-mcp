package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Privy backend (SIGNER_BACKEND=privy). The wallet key stays with Privy and every request is
// checked against the wallet's policy: typed data goes as eth_signTypedData_v4, transactions as
// eth_signTransaction and the agent-auth message as personal_sign, each of which the policy can
// inspect. Raw hashes (secp256k1_sign, raw_sign) are never sent.

const privyDefaultBase = "https://api.privy.io"

var privyWalletID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type privyClient struct {
	base, appID, secret string
	cred                *p256Credential
	http                *http.Client
}

func (c *privyClient) do(ctx context.Context, method, path string, body []byte) (map[string]any, error) {
	url := c.base + path
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.secret)))
	req.Header.Set("privy-app-id", c.appID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		sig, _, err := c.cred.privySignature(method, url, body, c.appID)
		if err != nil {
			return nil, err
		}
		req.Header.Set("privy-authorization-signature", sig)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Privy %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Privy %s %s: HTTP %d: %s", method, path, resp.StatusCode, privyError(raw))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("Privy %s %s: decode response: %w", method, path, err)
	}
	return out, nil
}

// privyError keeps both the error code (policy_violation) and the message.
func privyError(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		var parts []string
		for _, k := range []string{"error", "code", "message"} {
			if s, ok := m[k].(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, ": ")
		}
	}
	return providerMessage(raw)
}

type privySigner struct {
	c        *privyClient
	walletID string
	addr     common.Address
}

func (s *privySigner) Address() common.Address { return s.addr }

func (s *privySigner) SignDigest(context.Context, [32]byte) ([]byte, error) {
	return nil, errRawDigestRefused
}

func (s *privySigner) rpc(ctx context.Context, method string, params map[string]any, field string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	if err != nil {
		return "", err
	}
	out, err := s.c.do(ctx, http.MethodPost, "/v1/wallets/"+s.walletID+"/rpc", body)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}
	data, _ := out["data"].(map[string]any)
	v, _ := data[field].(string)
	if v == "" {
		return "", fmt.Errorf("Privy %s returned no %s", method, field)
	}
	return v, nil
}

func (s *privySigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	payload, err := providerTypedDataJSON(td, "primary_type")
	if err != nil {
		return nil, err
	}
	sigHex, err := s.rpc(ctx, "eth_signTypedData_v4", map[string]any{"typed_data": payload}, "signature")
	if err != nil {
		return nil, err
	}
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		return nil, fmt.Errorf("Privy signature: %w", err)
	}
	return checkSig65(sig, [32]byte(hash), s.addr)
}

func (s *privySigner) SignPersonalMessage(ctx context.Context, msg []byte) ([]byte, error) {
	sigHex, err := s.rpc(ctx, "personal_sign", map[string]any{"message": hexutil.Encode(msg), "encoding": "hex"}, "signature")
	if err != nil {
		return nil, err
	}
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		return nil, fmt.Errorf("Privy signature: %w", err)
	}
	return checkSig65(sig, [32]byte(accounts.TextHash(msg)), s.addr)
}

func (s *privySigner) SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx.To() == nil {
		return nil, errors.New("Privy signing does not cover contract creation")
	}
	p := map[string]any{
		"to": strings.ToLower(tx.To().Hex()), "value": hexutil.EncodeBig(tx.Value()), "data": hexutil.Encode(tx.Data()),
		"chain_id": hexutil.EncodeBig(chainID), "nonce": hexutil.EncodeUint64(tx.Nonce()), "gas_limit": hexutil.EncodeUint64(tx.Gas()),
	}
	switch tx.Type() {
	case types.DynamicFeeTxType:
		p["type"] = 2
		p["max_fee_per_gas"] = hexutil.EncodeBig(tx.GasFeeCap())
		p["max_priority_fee_per_gas"] = hexutil.EncodeBig(tx.GasTipCap())
	case types.LegacyTxType:
		p["type"] = 0
		p["gas_price"] = hexutil.EncodeBig(tx.GasPrice())
	default:
		return nil, fmt.Errorf("transaction type %d is not supported by remote signing", tx.Type())
	}
	signedHex, err := s.rpc(ctx, "eth_signTransaction", map[string]any{"transaction": p}, "signed_transaction")
	if err != nil {
		return nil, err
	}
	signed, err := hexutil.Decode(signedHex)
	if err != nil {
		return nil, fmt.Errorf("Privy signed transaction: %w", err)
	}
	return attachProviderSig(signed, tx, chainID, s.addr)
}

// privyKeystore opens SIGNER_BACKEND=privy: AGENT_WALLETS maps agent ids to Privy wallet ids.
// Each wallet is fetched at boot; one with no owner is refused, because then the app secret alone
// can sign and replace the wallet's policy.
func privyKeystore(ctx context.Context, getenv func(string) string, wallets string) (*keystore, []string, error) {
	vals := map[string]string{}
	for _, k := range []string{"PRIVY_APP_ID", "PRIVY_APP_SECRET", "PRIVY_AUTHORIZATION_KEY"} {
		vals[k] = strings.TrimSpace(getenv(k))
		if vals[k] == "" {
			return nil, nil, fmt.Errorf("SIGNER_BACKEND=privy needs %s", k)
		}
	}
	cred, err := privyCredential(vals["PRIVY_AUTHORIZATION_KEY"])
	if err != nil {
		return nil, nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(getenv("PRIVY_API_BASE_URL")), "/")
	if base == "" {
		base = privyDefaultBase
	}
	c := &privyClient{base: base, appID: vals["PRIVY_APP_ID"], secret: vals["PRIVY_APP_SECRET"], cred: cred, http: &http.Client{}}
	return walletKeystore(ctx, wallets, "Privy wallet", func(ctx context.Context, id string) (Signer, error) {
		if !privyWalletID.MatchString(id) {
			return nil, fmt.Errorf("AGENT_WALLETS Privy entry %q is not a wallet id", id)
		}
		ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
		defer cancel()
		w, err := c.do(ctx, http.MethodGet, "/v1/wallets/"+id, nil)
		if err != nil {
			return nil, fmt.Errorf("Privy wallet %s: %w", id, err)
		}
		addr, _ := w["address"].(string)
		if !common.IsHexAddress(addr) || w["chain_type"] != "ethereum" {
			return nil, fmt.Errorf("Privy wallet %s is not an Ethereum wallet", id)
		}
		if owner, _ := w["owner_id"].(string); owner == "" {
			return nil, fmt.Errorf("Privy wallet %s has no owner, so the app secret alone can sign and replace its policy; create it with an owner key quorum and add this signer as an additional signer (see docs/signer-policies)", id)
		}
		return &privySigner{c: c, walletID: id, addr: common.HexToAddress(addr)}, nil
	})
}
