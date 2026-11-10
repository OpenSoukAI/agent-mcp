package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── sign_tos_acceptance ─────────────────────────────────────────────────────────
//
// Accepting the Terms of Service is a legal act of the identity's owner, so unlike the commitment
// signers this tool never signs on its own initiative: a call without accept_version only returns
// the text to show the user, and a signature needs accept_version naming the version they agreed
// to. The message is the backend's frozen TosAcceptance type (backend internal/signing,
// testdata/tos_acceptance_vectors.json pins it).

const (
	tosTypeString    = "TosAcceptance(string role,uint256 identityId,string tosVersion,bytes32 tosHash,bytes32 nameEmailHash,string statement,uint64 signedAt)"
	tosDomainName    = "OpenSouk Terms"
	tosDomainVersion = "1"
	tosDomainType    = "EIP712Domain(string name,string version,uint256 chainId)"
)

var (
	tosTypehash       = crypto.Keccak256Hash([]byte(tosTypeString))
	tosDomainTypehash = crypto.Keccak256Hash([]byte(tosDomainType))
)

type tosMessage struct {
	Role          string
	IdentityID    *big.Int
	TosVersion    string
	TosHash       [32]byte
	NameEmailHash [32]byte
	Statement     string
	SignedAt      uint64
}

// tosNameEmailHash is keccak256(name || 0x00 || lowercase(email)), as the backend hashes it.
func tosNameEmailHash(name, email string) [32]byte {
	return crypto.Keccak256Hash([]byte(name), []byte{0}, []byte(strings.ToLower(email)))
}

// tosDigest is the hand-rolled EIP-712 digest that signTyped checks the typed data against.
func tosDigest(m tosMessage, chainID int64) ([]byte, error) {
	domain, err := abi.Arguments{{Type: mustABIType("bytes32")}, {Type: mustABIType("bytes32")}, {Type: mustABIType("bytes32")}, {Type: mustABIType("uint256")}}.
		Pack(tosDomainTypehash, crypto.Keccak256Hash([]byte(tosDomainName)), crypto.Keccak256Hash([]byte(tosDomainVersion)), big.NewInt(chainID))
	if err != nil {
		return nil, err
	}
	b32 := mustABIType("bytes32")
	packed, err := abi.Arguments{{Type: b32}, {Type: b32}, {Type: mustABIType("uint256")}, {Type: b32}, {Type: b32}, {Type: b32}, {Type: b32}, {Type: mustABIType("uint64")}}.
		Pack(tosTypehash, crypto.Keccak256Hash([]byte(m.Role)), m.IdentityID, crypto.Keccak256Hash([]byte(m.TosVersion)),
			m.TosHash, m.NameEmailHash, crypto.Keccak256Hash([]byte(m.Statement)), m.SignedAt)
	if err != nil {
		return nil, err
	}
	d, s := crypto.Keccak256Hash(domain), crypto.Keccak256Hash(packed)
	return crypto.Keccak256([]byte{0x19, 0x01}, d[:], s[:]), nil
}

// tosTypedData is the same message as structured EIP-712 data. Its domain has no
// verifyingContract (no contract verifies it), so the shared typedData helper does not fit.
func tosTypedData(m tosMessage, chainID int64) apitypes.TypedData {
	return apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}},
			"TosAcceptance": {
				{Name: "role", Type: "string"}, {Name: "identityId", Type: "uint256"}, {Name: "tosVersion", Type: "string"},
				{Name: "tosHash", Type: "bytes32"}, {Name: "nameEmailHash", Type: "bytes32"}, {Name: "statement", Type: "string"},
				{Name: "signedAt", Type: "uint64"},
			},
		},
		PrimaryType: "TosAcceptance",
		Domain:      apitypes.TypedDataDomain{Name: tosDomainName, Version: tosDomainVersion, ChainId: math.NewHexOrDecimal256(chainID)},
		Message: apitypes.TypedDataMessage{
			"role": m.Role, "identityId": m.IdentityID.String(), "tosVersion": m.TosVersion,
			"tosHash": hexutil.Encode(m.TosHash[:]), "nameEmailHash": hexutil.Encode(m.NameEmailHash[:]),
			"statement": m.Statement, "signedAt": strconv.FormatUint(m.SignedAt, 10),
		},
	}
}

// signTos signs m through signTyped (the typed data must hash to the hand-rolled digest) and
// returns v as 27/28, like every other signature this signer emits and the backend's vectors.
func signTos(ctx context.Context, key Signer, m tosMessage, chainID int64) ([]byte, error) {
	want, err := tosDigest(m, chainID)
	if err != nil {
		return nil, err
	}
	sig, err := signTyped(ctx, key, tosTypedData(m, chainID), want)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 && sig[64] < 27 {
		sig[64] += 27
	}
	return sig, nil
}

type tosVersionInfo struct {
	Version     string `json:"version"`
	Hash        string `json:"hash"`
	URL         string `json:"url"`
	Statement   string `json:"statement"`
	EffectiveAt string `json:"effective_at"`
}

type tosCurrentResponse struct {
	tosVersionInfo
	ChainID  int64           `json:"chain_id"`
	Upcoming *tosVersionInfo `json:"upcoming"`
}

type signTosAcceptanceInput struct {
	Role          string `json:"role"`                     // merchant | reviewer
	IdentityID    string `json:"identity_id"`              // decimal; merchant_id or agent_id
	ContactName   string `json:"contact_name,omitempty"`   // merchant only: the merchant's (business) name
	ContactEmail  string `json:"contact_email,omitempty"`  // merchant only: where legal notices go
	AcceptVersion string `json:"accept_version,omitempty"` // empty: preview only; else the version the user accepted
}

type signTosAcceptanceOutput struct {
	Status     string          `json:"status"` // "preview" or "accepted"
	Role       string          `json:"role"`
	IdentityID string          `json:"identity_id"`
	Current    *tosVersionInfo `json:"current,omitempty"`  // preview: the version in force
	Upcoming   *tosVersionInfo `json:"upcoming,omitempty"` // preview: the next version, signable now
	// accepted:
	SignedVersion   string `json:"signed_version,omitempty"`
	Signer          string `json:"signer,omitempty"`
	TosStatus       string `json:"tos_status,omitempty"` // merchant only
	CanTrade        *bool  `json:"can_trade,omitempty"`  // merchant only
	UpcomingVersion string `json:"upcoming_version,omitempty"`
	SignBy          string `json:"sign_by,omitempty"`
	Next            string `json:"next"`
}

func handleSignTosAcceptance(ctx context.Context, _ *sdkmcp.CallToolRequest, in signTosAcceptanceInput) (*sdkmcp.CallToolResult, signTosAcceptanceOutput, error) {
	const tool = "sign_tos_acceptance"
	if in.Role != "merchant" && in.Role != "reviewer" {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("role must be merchant or reviewer, got %q", in.Role)
	}
	id, err := parseMerchantID(in.IdentityID)
	if err != nil {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("identity_id: %w", err)
	}
	restID, err := merchantIDForREST(id)
	if err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	if in.Role == "merchant" && (in.ContactName == "" || in.ContactEmail == "") {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("a merchant acceptance needs contact_name (the merchant's business name) and contact_email (where legal notices go)")
	}
	if in.Role == "reviewer" && (in.ContactName != "" || in.ContactEmail != "") {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("a reviewer acceptance carries no contact: drop contact_name and contact_email")
	}
	chainID, err := configuredChainID()
	if err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	cur, err := fetchTosCurrent(ctx, in.Role, chainID)
	if err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	out := signTosAcceptanceOutput{Role: in.Role, IdentityID: id.String()}

	if in.AcceptVersion == "" {
		c := cur.tosVersionInfo
		out.Status, out.Current, out.Upcoming = "preview", &c, cur.Upcoming
		out.Next = "Nothing was signed. Show the user the statement and the url of the version to accept (current, or upcoming if " +
			"one is listed: it can be signed now and takes effect at its effective_at) and ask whether they accept those Terms. " +
			"Only if they say yes, call sign_tos_acceptance again with the same inputs and accept_version set to that version. " +
			"Never accept on the user's behalf."
		return nil, out, nil
	}

	target := cur.tosVersionInfo
	if cur.Upcoming != nil && in.AcceptVersion == cur.Upcoming.Version {
		target = *cur.Upcoming
	} else if in.AcceptVersion != cur.Version {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("%q is not the %s ToS in force (%s) or the announced next version: nothing was signed; call again without accept_version and show the user the current text",
			in.AcceptVersion, in.Role, describeSignable(cur))
	}
	if err := requireAgentAuth(tool, id); err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	key, err := signerKeys.KeyFor(id.String())
	if err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	if _, ok := key.(*privySigner); ok {
		// Provider policy v2 (docs/signer-policies) allows no TosAcceptance, so Privy would refuse it.
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("%s: the Privy policy (v2) does not allow signing the Terms of Service; nothing was signed. Accept them from the dashboard with the owner wallet", tool)
	}
	hash, err := hexutil.Decode(target.Hash)
	if err != nil || len(hash) != 32 {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("the backend sent an invalid ToS hash %q", target.Hash)
	}
	msg := tosMessage{Role: in.Role, IdentityID: id, TosVersion: target.Version, Statement: target.Statement,
		SignedAt: uint64(time.Now().Unix())}
	copy(msg.TosHash[:], hash)
	if in.Role == "merchant" {
		msg.NameEmailHash = tosNameEmailHash(in.ContactName, in.ContactEmail)
	}
	sig, err := signTos(ctx, key, msg, cur.ChainID)
	if err != nil {
		return nil, signTosAcceptanceOutput{}, fmt.Errorf("%s: sign: %w", tool, err)
	}

	body := map[string]any{"role": in.Role, "identity_id": restID, "tos_version": msg.TosVersion,
		"signed_at": msg.SignedAt, "signature": hexutil.Encode(sig)}
	if in.Role == "merchant" {
		body["contact_name"], body["contact_email"] = in.ContactName, in.ContactEmail
	}
	raw, _ := json.Marshal(body)
	resp, err := callAuthedJSON(ctx, tool, http.MethodPost, "/v1/tos/acceptance?chain_id="+strconv.FormatInt(cur.ChainID, 10), raw, id, map[int]string{
		http.StatusForbidden: "the signing key is not the identity's current on-chain owner. If the owner is a Safe or another " +
			"wallet, the acceptance must be signed by that owner (for a Safe, through the dashboard)",
		http.StatusNotFound:            "for a merchant: register it first (activate_merchant); otherwise check that identity_id exists on this chain",
		http.StatusConflict:            "the ToS changed since the text was shown: call again without accept_version and show the user the new text",
		http.StatusUnprocessableEntity: "the owner wallet is not deployed yet: deploy it, then sign again",
	})
	if err != nil {
		return nil, signTosAcceptanceOutput{}, err
	}
	out.Status, out.SignedVersion, out.Signer = "accepted", msg.TosVersion, stringField(resp, "signer")
	if in.Role == "merchant" {
		out.TosStatus = stringField(resp, "tos_status")
		if v, ok := resp["can_trade"].(bool); ok {
			out.CanTrade = &v
		}
		out.UpcomingVersion, out.SignBy = stringField(resp, "upcoming_version"), stringField(resp, "sign_by")
	}
	out.Next = "Recorded. Tell the user which version they accepted."
	if out.UpcomingVersion != "" {
		out.Next += " A newer version " + out.UpcomingVersion + " must also be accepted by " + out.SignBy + ": run the preview again to show it."
	}
	return nil, out, nil
}

func describeSignable(cur tosCurrentResponse) string {
	if cur.Upcoming != nil {
		return cur.Version + ", next " + cur.Upcoming.Version
	}
	return cur.Version
}

// fetchTosCurrent reads GET /v1/tos/current, which needs no auth.
func fetchTosCurrent(ctx context.Context, role string, chainID int64) (tosCurrentResponse, error) {
	base, err := apiBaseURL()
	if err != nil {
		return tosCurrentResponse{}, err
	}
	u := base + "/v1/tos/current?role=" + url.QueryEscape(role) + "&chain_id=" + strconv.FormatInt(chainID, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return tosCurrentResponse{}, err
	}
	resp, err := (&http.Client{Timeout: restTimeout}).Do(req)
	if err != nil {
		return tosCurrentResponse{}, fmt.Errorf("sign_tos_acceptance: GET /v1/tos/current: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return tosCurrentResponse{}, fmt.Errorf("no %s Terms of Service are published on chain %d yet: there is nothing to accept", role, chainID)
	}
	if resp.StatusCode != http.StatusOK {
		return tosCurrentResponse{}, restError("sign_tos_acceptance", resp.StatusCode, raw, nil)
	}
	var cur tosCurrentResponse
	if err := json.Unmarshal(raw, &cur); err != nil {
		return tosCurrentResponse{}, fmt.Errorf("sign_tos_acceptance: decode /v1/tos/current: %w", err)
	}
	if cur.ChainID != chainID {
		return tosCurrentResponse{}, fmt.Errorf("the backend answered for chain %d, this signer serves %d: check REFERRER_API_URL and CHAIN_ID", cur.ChainID, chainID)
	}
	return cur, nil
}
