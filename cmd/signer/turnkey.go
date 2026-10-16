package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Turnkey backend (SIGNER_BACKEND=turnkey). The wallet key stays in Turnkey's enclave and every
// signature is an activity its policy engine evaluates: typed data is sent as EIP-712 so the
// policy sees the primary type, domain and message, and transactions are sent whole so it sees
// the destination. Raw digests and personal messages are refused: Turnkey can sign those only as
// raw payloads, which its policy cannot inspect.

const turnkeyDefaultBase = "https://api.turnkey.com"

var (
	turnkeyPollInterval = 500 * time.Millisecond
	// providerCallTimeout bounds one signature end to end, including Turnkey's activity polling.
	providerCallTimeout = 30 * time.Second
)

type turnkeyClient struct {
	base, org string
	cred      *p256Credential
	http      *http.Client
}

func (c *turnkeyClient) post(ctx context.Context, path string, body any) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	stamp, err := c.cred.turnkeyStamp(b)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stamp", stamp)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Turnkey %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Turnkey %s: HTTP %d: %s", path, resp.StatusCode, providerMessage(raw))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("Turnkey %s: decode response: %w", path, err)
	}
	return out, nil
}

// providerMessage is the human part of a provider error body, capped.
func providerMessage(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		for _, k := range []string{"message", "error", "details"} {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// whoami checks the API key against the organization and returns the user it belongs to.
func (c *turnkeyClient) whoami(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	out, err := c.post(ctx, "/public/v1/query/whoami", map[string]any{"organizationId": c.org})
	if err != nil {
		return "", err
	}
	if out["organizationId"] != c.org {
		return "", fmt.Errorf("whoami answered for organization %v", out["organizationId"])
	}
	user, _ := out["userId"].(string)
	return user, nil
}

// activity submits a Turnkey activity and waits for it to finish, returning its result.
func (c *turnkeyClient) activity(ctx context.Context, path, typ string, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	resp, err := c.post(ctx, path, map[string]any{
		"type": typ, "timestampMs": strconv.FormatInt(time.Now().UnixMilli(), 10), "organizationId": c.org, "parameters": params,
	})
	if err != nil {
		return nil, err
	}
	for {
		act, _ := resp["activity"].(map[string]any)
		status, _ := act["status"].(string)
		id, _ := act["id"].(string)
		switch status {
		case "ACTIVITY_STATUS_COMPLETED":
			res, _ := act["result"].(map[string]any)
			if res == nil {
				return nil, fmt.Errorf("Turnkey activity %s completed without a result", id)
			}
			return res, nil
		case "ACTIVITY_STATUS_FAILED", "ACTIVITY_STATUS_REJECTED":
			msg := ""
			if f, ok := act["failure"].(map[string]any); ok {
				msg, _ = f["message"].(string)
			}
			return nil, fmt.Errorf("Turnkey refused activity %s (%s): %s", id, status, msg)
		}
		waitErr := func() error {
			if status == "ACTIVITY_STATUS_CONSENSUS_NEEDED" {
				return fmt.Errorf("Turnkey activity %s needs approval in the Turnkey dashboard before it can sign; gave up after %s", id, providerCallTimeout)
			}
			return fmt.Errorf("Turnkey activity %s still %s after %s", id, status, providerCallTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, waitErr()
		case <-time.After(turnkeyPollInterval):
		}
		resp, err = c.post(ctx, "/public/v1/query/get_activity", map[string]any{"organizationId": c.org, "activityId": id})
		if err != nil {
			if ctx.Err() != nil {
				return nil, waitErr()
			}
			return nil, err
		}
	}
}

type turnkeySigner struct {
	c    *turnkeyClient
	addr common.Address
}

func (s *turnkeySigner) Address() common.Address { return s.addr }

func (s *turnkeySigner) SignDigest(context.Context, [32]byte) ([]byte, error) {
	return nil, errRawDigestRefused
}

func (s *turnkeySigner) SignPersonalMessage(context.Context, []byte) ([]byte, error) {
	return nil, s.agentAuthRefusal()
}

func (s *turnkeySigner) agentAuthRefusal() error {
	return errors.New("SIGNER_BACKEND=turnkey cannot personal-sign: Turnkey signs a message only as a raw payload, which its policy cannot inspect. The merchant REST tools need it; run them with SIGNER_BACKEND=privy, kms or local")
}

func (s *turnkeySigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	payload, err := providerTypedDataJSON(td, "primaryType", true)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	res, err := s.c.activity(ctx, "/public/v1/submit/sign_raw_payload", "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", map[string]any{
		"signWith": s.addr.Hex(), "payload": string(b),
		"encoding": "PAYLOAD_ENCODING_EIP712", "hashFunction": "HASH_FUNCTION_NO_OP",
	})
	if err != nil {
		return nil, err
	}
	out, _ := res["signRawPayloadResult"].(map[string]any)
	r, rok := hexBig(out["r"])
	sv, sok := hexBig(out["s"])
	if !rok || !sok {
		return nil, errors.New("Turnkey returned no r/s for the typed-data signature")
	}
	return normaliseSig(r, sv, [32]byte(hash), s.addr)
}

func (s *turnkeySigner) SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	raw, err := unsignedTxRLP(tx, chainID)
	if err != nil {
		return nil, err
	}
	res, err := s.c.activity(ctx, "/public/v1/submit/sign_transaction", "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", map[string]any{
		"signWith": s.addr.Hex(), "unsignedTransaction": hex.EncodeToString(raw), "type": "TRANSACTION_TYPE_ETHEREUM",
	})
	if err != nil {
		return nil, err
	}
	out, _ := res["signTransactionResult"].(map[string]any)
	signedHex, _ := out["signedTransaction"].(string)
	signed, err := hex.DecodeString(strings.TrimPrefix(signedHex, "0x"))
	if err != nil || len(signed) == 0 {
		return nil, errors.New("Turnkey returned no signed transaction")
	}
	return attachProviderSig(signed, tx, chainID, s.addr)
}

func hexBig(v any) (*big.Int, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, false
	}
	return new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
}

// turnkeyKeystore opens SIGNER_BACKEND=turnkey: AGENT_WALLETS maps agent ids to Turnkey wallet
// account addresses. The API key is checked against Turnkey (whoami) before any tool runs.
func turnkeyKeystore(ctx context.Context, getenv func(string) string, wallets string) (*keystore, []string, error) {
	vals := map[string]string{}
	for _, k := range []string{"TURNKEY_ORG_ID", "TURNKEY_API_PUBLIC_KEY", "TURNKEY_API_PRIVATE_KEY"} {
		vals[k] = strings.TrimSpace(getenv(k))
		if vals[k] == "" {
			return nil, nil, fmt.Errorf("SIGNER_BACKEND=turnkey needs %s", k)
		}
	}
	cred, err := turnkeyCredential(vals["TURNKEY_API_PRIVATE_KEY"], vals["TURNKEY_API_PUBLIC_KEY"])
	if err != nil {
		return nil, nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(getenv("TURNKEY_API_BASE_URL")), "/")
	if base == "" {
		base = turnkeyDefaultBase
	}
	c := &turnkeyClient{base: base, org: vals["TURNKEY_ORG_ID"], cred: cred, http: &http.Client{}}
	user, err := c.whoami(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("Turnkey whoami with TURNKEY_API_PUBLIC_KEY failed (check the key belongs to a user in TURNKEY_ORG_ID): %w", err)
	}
	ks, report, err := walletKeystore(ctx, wallets, "Turnkey wallet", func(_ context.Context, ref string) (Signer, error) {
		if !common.IsHexAddress(ref) {
			return nil, fmt.Errorf("AGENT_WALLETS Turnkey entry %q is not a wallet account address", ref)
		}
		return &turnkeySigner{c: c, addr: common.HexToAddress(ref)}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return ks, append(report, "Turnkey API user "+user+" (the policy's --turnkey-user-id)"), nil
}
