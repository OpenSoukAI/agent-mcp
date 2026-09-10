package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
	x402types "github.com/x402-foundation/x402/go/types"
)

// ── EIP-712 type strings (must match ReviewRegistry contract exactly) ──────────

const (
	domainTypeString     = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	commitmentTypeString = "ReviewCommitment(uint256 agentId,uint256 merchantId,bytes32 productId,bytes32 contentHash,uint256 nonce,uint256 expiry)"
)

var (
	domainTypehash     = crypto.Keccak256Hash([]byte(domainTypeString))
	commitmentTypehash = crypto.Keccak256Hash([]byte(commitmentTypeString))

	reviewPublishedTopic      = crypto.Keccak256Hash([]byte("ReviewPublished(uint256,uint256,uint256,bytes32,bytes32,uint8,uint40)"))
	escrowDepositedTopic      = crypto.Keccak256Hash([]byte("EscrowDeposited(uint256,uint256,uint256,address,uint256,uint256,bytes32,uint128,uint128)"))
	fallbackSettledTopic      = crypto.Keccak256Hash([]byte("FallbackSettled(uint256,address,uint128,uint128)"))
	reviewContentUpdatedTopic = crypto.Keccak256Hash([]byte("ReviewContentUpdated(uint256,bytes32,uint40)"))

	abiUint256 = mustABIType("uint256")
	abiBytes32 = mustABIType("bytes32")
	abiAddress = mustABIType("address")
	abiString  = mustABIType("string")

	reviewRegistryABI = mustParseABI(`[
		{"inputs":[{"name":"agentId","type":"uint256"},{"name":"contentHash","type":"bytes32"},{"name":"escrowId","type":"uint256"}],"name":"publishReviewWithEscrowProof","outputs":[{"name":"reviewId","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"reviewId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"merchantId","type":"uint256"},{"indexed":false,"name":"productId","type":"bytes32"},{"indexed":false,"name":"contentHash","type":"bytes32"},{"indexed":false,"name":"proofType","type":"uint8"},{"indexed":false,"name":"timestamp","type":"uint40"}],"name":"ReviewPublished","type":"event"},
		{"inputs":[{"name":"reviewId","type":"uint256"}],"name":"getReview","outputs":[{"components":[{"name":"agentId","type":"uint256"},{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"contentHash","type":"bytes32"},{"name":"proofType","type":"uint8"},{"name":"timestamp","type":"uint40"},{"name":"editedAt","type":"uint40"}],"name":"","type":"tuple"}],"stateMutability":"view","type":"function"},
		{"inputs":[{"name":"reviewId","type":"uint256"},{"name":"newContentHash","type":"bytes32"}],"name":"updateReviewContent","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"reviewId","type":"uint256"},{"indexed":true,"name":"contentHash","type":"bytes32"},{"indexed":false,"name":"editedAt","type":"uint40"}],"name":"ReviewContentUpdated","type":"event"}
	]`)

	commissionEscrowABI = mustParseABI(`[
		{"inputs":[{"name":"escrowId","type":"uint256"}],"name":"getEscrow","outputs":[{"components":[{"name":"reviewerAgentId","type":"uint256"},{"name":"buyerAgentId","type":"uint256"},{"name":"buyerWallet","type":"address"},{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"heldBackAmt","type":"uint128"},{"name":"cashbackAmt","type":"uint128"},{"name":"originalPurchaseAmt","type":"uint128"},{"name":"depositTimestamp","type":"uint40"},{"name":"windowEnd","type":"uint40"},{"name":"productType","type":"uint8"},{"name":"state","type":"uint8"},{"name":"cashbackReleased","type":"bool"}],"name":"","type":"tuple"}],"stateMutability":"view","type":"function"},
		{"inputs":[{"name":"escrowId","type":"uint256"},{"name":"agentId","type":"uint256"}],"name":"bind","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"escrowId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"boundBy","type":"address"}],"name":"EscrowBound","type":"event"},
		{"inputs":[{"name":"escrowId","type":"uint256"}],"name":"triggerSettleFallback","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"escrowId","type":"uint256"},{"indexed":true,"name":"treasury","type":"address"},{"indexed":false,"name":"heldBackAmt","type":"uint128"},{"indexed":false,"name":"cashbackAmt","type":"uint128"}],"name":"FallbackSettled","type":"event"}
	]`)

	// MerchantRegistry and ProductRegistry carry the merchant-side writes (REF-251). Both
	// literals are trimmed to what the tools call; entries are added when a tool needs one,
	// so an unused entry here means something was removed and its ABI was not.
	//
	// merchantId IS the ERC-8004 agentId — MerchantRegistry mints nothing. isActive is here
	// because setActive's receipt does not prove the flag: a suspended merchant's
	// self-reactivation reverts, and only a read distinguishes that from success.
	merchantRegistryABI = mustParseABI(`[
		{"inputs":[{"name":"merchantId","type":"uint256"},{"name":"active","type":"bool"}],"name":"setActive","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[{"name":"merchantId","type":"uint256"}],"name":"isActive","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"}
	]`)

	// productType is `enum ProductType` in Solidity, which the ABI flattens to uint8. The
	// ordinals are hand-mirrored in productType* below and nothing in the ABI would catch a
	// reordering of the enum.
	productRegistryABI = mustParseABI(`[
		{"inputs":[{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"commissionBps","type":"uint16"},{"name":"productType","type":"uint8"},{"name":"productCardURI","type":"string"}],"name":"addProduct","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"commissionBps","type":"uint16"}],"name":"setCommission","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"active","type":"bool"}],"name":"setProductActive","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"}],"name":"getProduct","outputs":[{"components":[{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"commissionBps","type":"uint16"},{"name":"active","type":"bool"},{"name":"productCardURI","type":"string"},{"name":"createdAt","type":"uint40"},{"name":"productType","type":"uint8"}],"name":"","type":"tuple"}],"stateMutability":"view","type":"function"}
	]`)
)

// ProductType ordinals, mirrored from IProductRegistry.ProductType. Enum member names are
// absent from the ABI, so a reordering in Solidity leaves both repos compiling and green
// while every add_product call writes the wrong type.
const (
	productTypeRepeat uint8 = 0
	productTypeOneOff uint8 = 1
)

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(fmt.Sprintf("abi.NewType(%q): %v", t, err))
	}
	return typ
}

func mustParseABI(s string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(fmt.Sprintf("abi.JSON: %v", err))
	}
	return a
}

// ── ReviewCommitmentPayload mirrors the backend signing.ReviewCommitmentPayload ─
//
// The backend returns a full EIP-712 typed-data object that includes Types and
// PrimaryType (for eth_signTypedData_v4 wallet RPC compatibility). The signer
// recomputes the digest from Domain + Message directly, so it ignores those
// fields — but the struct must accept them to avoid MCP schema validation
// errors when the agent passes the unstripped commitment object (F-02).

type commitmentDomain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainID           int64  `json:"chainId"`
	VerifyingContract string `json:"verifyingContract"`
}

type commitmentMessage struct {
	AgentID     string `json:"agentId"`
	MerchantID  string `json:"merchantId"`
	ProductID   string `json:"productId"`
	ContentHash string `json:"contentHash"`
	Nonce       string `json:"nonce"`
	Expiry      string `json:"expiry"`
}

type reviewCommitmentPayload struct {
	// Types and PrimaryType are part of the EIP-712 typed-data envelope returned
	// by submit_admin_approved_review step 1. Accepted here but not used — the signer recomputes
	// the digest from Domain + Message directly.
	Types       map[string]any    `json:"types,omitempty"`
	PrimaryType string            `json:"primaryType,omitempty"`
	Domain      commitmentDomain  `json:"domain"`
	Message     commitmentMessage `json:"message"`
}

// ── sign_review_commitment ─────────────────────────────────────────────────────

type signInput struct {
	Commitment reviewCommitmentPayload `json:"commitment"`
}

type signOutput struct {
	// 0x-prefixed 65-byte hex signature. Pass directly as agent_sig in submit_admin_approved_review step 2.
	Signature string `json:"signature"`
}

// ── EIP-712 digest (mirrors backend signing.RecoverEIP712Signer exactly) ──────

func computeDigest(p reviewCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(p.Domain.Name)),
		crypto.Keccak256Hash([]byte(p.Domain.Version)),
		chainID,
		contractAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	agentID, ok := new(big.Int).SetString(p.Message.AgentID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid agentId: %q", p.Message.AgentID)
	}
	merchantID, ok := new(big.Int).SetString(p.Message.MerchantID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid merchantId: %q", p.Message.MerchantID)
	}
	nonce, ok := new(big.Int).SetString(p.Message.Nonce, 10)
	if !ok {
		return nil, fmt.Errorf("invalid nonce: %q", p.Message.Nonce)
	}
	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}

	productID, err := hexToBytes32(p.Message.ProductID)
	if err != nil {
		return nil, fmt.Errorf("invalid productId: %w", err)
	}
	contentHash, err := hexToBytes32(p.Message.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("invalid contentHash: %w", err)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiUint256}, {Type: abiUint256},
		{Type: abiBytes32}, {Type: abiBytes32},
		{Type: abiUint256}, {Type: abiUint256},
	}.Pack(
		commitmentTypehash,
		agentID, merchantID,
		productID, contentHash,
		nonce, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("must be 0x-prefixed 32-byte hex")
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// keystore holds the signing keys parsed once at startup. agentID is the decimal string.
type keystore struct {
	keys     map[string]*ecdsa.PrivateKey
	fallback *ecdsa.PrivateKey
}

// parseKeystore parses AGENT_KEYS (comma-separated "agentId:0xkey") + the AGENT_PRIVATE_KEY
// fallback, validating every key at boot. Fails if no keys are configured or any entry is malformed.
func parseKeystore(agentKeys, agentPrivKey string) (*keystore, error) {
	ks := &keystore{keys: make(map[string]*ecdsa.PrivateKey)}
	if agentKeys != "" {
		for _, entry := range strings.Split(agentKeys, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			id, keyHex, ok := strings.Cut(entry, ":")
			if !ok {
				return nil, fmt.Errorf("AGENT_KEYS entry %q missing ':' (want agentId:0xkey)", entry)
			}
			id = strings.TrimSpace(id)
			if id == "" {
				return nil, fmt.Errorf("AGENT_KEYS entry %q has empty agentId", entry)
			}
			key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(keyHex), "0x"))
			if err != nil {
				return nil, fmt.Errorf("AGENT_KEYS agent %s: invalid key: %w", id, err)
			}
			if _, dup := ks.keys[id]; dup {
				return nil, fmt.Errorf("AGENT_KEYS duplicate agentId %s", id)
			}
			ks.keys[id] = key
		}
	}
	if agentPrivKey != "" {
		key, err := crypto.HexToECDSA(strings.TrimPrefix(agentPrivKey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("AGENT_PRIVATE_KEY: invalid key: %w", err)
		}
		ks.fallback = key
	}
	if len(ks.keys) == 0 && ks.fallback == nil {
		return nil, fmt.Errorf("no signing keys configured: set AGENT_KEYS or AGENT_PRIVATE_KEY")
	}
	return ks, nil
}

// KeyFor returns the signing key for agentID: exact AGENT_KEYS match first, then fallback.
func (ks *keystore) KeyFor(agentID string) (*ecdsa.PrivateKey, error) {
	if k, ok := ks.keys[agentID]; ok {
		return k, nil
	}
	if ks.fallback != nil {
		return ks.fallback, nil
	}
	return nil, fmt.Errorf("no key for agent %s — not in AGENT_KEYS and no AGENT_PRIVATE_KEY fallback", agentID)
}

// signerKeys is initialized once in main() before the server starts.
var signerKeys *keystore

func handleSign(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	digest, err := computeDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1

	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}

// ── VoteCommitment EIP-712 types (must match VoteRegistry contract exactly) ───

const voteCommitmentTypeString = "VoteCommitment(uint256 agentId,uint256 escrowId,bytes32 votesHash,uint256 nonce,uint256 expiry)"

var voteCommitmentTypehash = crypto.Keccak256Hash([]byte(voteCommitmentTypeString))

type voteCommitmentMessage struct {
	AgentID   string `json:"agentId"`
	EscrowID  string `json:"escrowId"`
	VotesHash string `json:"votesHash"`
	Nonce     string `json:"nonce"`
	Expiry    string `json:"expiry"`
}

type voteCommitmentPayload struct {
	// Types and PrimaryType: same as reviewCommitmentPayload — accepted but ignored.
	Types       map[string]any        `json:"types,omitempty"`
	PrimaryType string                `json:"primaryType,omitempty"`
	Domain      commitmentDomain      `json:"domain"`
	Message     voteCommitmentMessage `json:"message"`
}

// ── sign_vote_commitment ───────────────────────────────────────────────────────

type signVoteInput struct {
	Commitment voteCommitmentPayload `json:"commitment"`
}

func computeVoteDigest(p voteCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(p.Domain.Name)),
		crypto.Keccak256Hash([]byte(p.Domain.Version)),
		chainID,
		contractAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	agentID, ok := new(big.Int).SetString(p.Message.AgentID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid agentId: %q", p.Message.AgentID)
	}
	escrowID, ok := new(big.Int).SetString(p.Message.EscrowID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid escrowId: %q", p.Message.EscrowID)
	}
	nonce, ok := new(big.Int).SetString(p.Message.Nonce, 10)
	if !ok {
		return nil, fmt.Errorf("invalid nonce: %q", p.Message.Nonce)
	}
	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}
	votesHash, err := hexToBytes32(p.Message.VotesHash)
	if err != nil {
		return nil, fmt.Errorf("invalid votesHash: %w", err)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiUint256}, {Type: abiUint256},
		{Type: abiBytes32},
		{Type: abiUint256}, {Type: abiUint256},
	}.Pack(
		voteCommitmentTypehash,
		agentID, escrowID,
		votesHash,
		nonce, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignVote(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signVoteInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	digest, err := computeVoteDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1

	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}

// ── CashbackRateCommitment EIP-712 (must match backend signing/cashback_rate_commitment.go exactly) ──

const cashbackRateCommitmentTypeString = "CashbackRateCommitment(uint256 agentId,uint16 cashbackOfCommissionBps,bytes32 nonce,uint256 expiry)"

var cashbackRateCommitmentTypehash = crypto.Keccak256Hash([]byte(cashbackRateCommitmentTypeString))

const cashbackRateDomainName = "ReferrerCashbackRate"

type cashbackRateCommitmentMessage struct {
	AgentID                 string `json:"agentId"`
	CashbackOfCommissionBps string `json:"cashbackOfCommissionBps"`
	Nonce                   string `json:"nonce"`
	Expiry                  string `json:"expiry"`
}

type cashbackRateCommitmentPayload struct {
	// Types and PrimaryType are part of the EIP-712 typed-data envelope — accepted but ignored.
	Types       map[string]any                `json:"types,omitempty"`
	PrimaryType string                        `json:"primaryType,omitempty"`
	Domain      commitmentDomain              `json:"domain"`
	Message     cashbackRateCommitmentMessage `json:"message"`
}

// ── sign_cashback_rate_commitment ──────────────────────────────────────────────

type signCashbackRateInput struct {
	Commitment cashbackRateCommitmentPayload `json:"commitment"`
}

func computeCashbackRateDigest(p cashbackRateCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(p.Domain.Name)),
		crypto.Keccak256Hash([]byte(p.Domain.Version)),
		chainID,
		contractAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	agentID, ok := new(big.Int).SetString(p.Message.AgentID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid agentId: %q", p.Message.AgentID)
	}
	bpsBig, ok := new(big.Int).SetString(p.Message.CashbackOfCommissionBps, 10)
	if !ok {
		return nil, fmt.Errorf("invalid cashbackOfCommissionBps: %q", p.Message.CashbackOfCommissionBps)
	}
	if !bpsBig.IsUint64() || bpsBig.Uint64() > 65535 {
		return nil, fmt.Errorf("cashbackOfCommissionBps out of uint16 range: %s", bpsBig)
	}
	bps := uint16(bpsBig.Uint64())

	nonce, err := hexToBytes32(p.Message.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}

	abiUint16, err := abi.NewType("uint16", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi uint16: %w", err)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiUint16},
		{Type: abiBytes32},
		{Type: abiUint256},
	}.Pack(
		cashbackRateCommitmentTypehash,
		agentID, bps, nonce, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignCashbackRate(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signCashbackRateInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	digest, err := computeCashbackRateDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1

	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}

// ── publish_escrow_review ──────────────────────────────────────────────────────

type publishEscrowReviewInput struct {
	AgentID     string `json:"agent_id"`     // decimal string
	MerchantID  string `json:"merchant_id"`  // decimal string
	ProductID   string `json:"product_id"`   // 0x-prefixed 32-byte hex
	ContentJSON string `json:"content_json"` // raw JSON string of review content
	EscrowID    string `json:"escrow_id"`    // decimal string
}

type publishEscrowReviewOutput struct {
	ReviewID string `json:"review_id"` // decimal string
	TxHash   string `json:"tx_hash"`   // 0x-prefixed hex
}

func computeContentHash(agentID, merchantID *big.Int, productID [32]byte, contentJSON string) ([32]byte, error) {
	packed, err := abi.Arguments{
		{Type: abiUint256},
		{Type: abiUint256},
		{Type: abiBytes32},
		{Type: abiString},
	}.Pack(agentID, merchantID, productID, contentJSON)
	if err != nil {
		return [32]byte{}, fmt.Errorf("pack content hash args: %w", err)
	}
	return crypto.Keccak256Hash(packed), nil
}

func extractReviewID(receipt *types.Receipt) (*big.Int, error) {
	for _, log := range receipt.Logs {
		if len(log.Topics) >= 2 && log.Topics[0] == reviewPublishedTopic {
			return new(big.Int).SetBytes(log.Topics[1].Bytes()), nil
		}
	}
	return nil, fmt.Errorf("ReviewPublished event not found in receipt")
}

func handlePublishEscrowReview(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in publishEscrowReviewInput,
) (*sdkmcp.CallToolResult, publishEscrowReviewOutput, error) {
	privKey, err := signerKeys.KeyFor(in.AgentID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}
	// Two addresses, and no chain_id input on this tool — hence requireAddr twice and an
	// empty override, rather than dialChain taking the addresses itself.
	registryAddr, err := requireAddr("REVIEW_REGISTRY_ADDRESS")
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}
	escrowAddr, err := requireAddr("COMMISSION_ESCROW_ADDRESS")
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}

	agentID, ok := new(big.Int).SetString(in.AgentID, 10)
	if !ok {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid agent_id: %q", in.AgentID)
	}
	callerMerchantID, ok := new(big.Int).SetString(in.MerchantID, 10)
	if !ok {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid merchant_id: %q", in.MerchantID)
	}
	escrowID, ok := new(big.Int).SetString(in.EscrowID, 10)
	if !ok {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid escrow_id: %q", in.EscrowID)
	}
	callerProductID, err := hexToBytes32(in.ProductID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid product_id: %w", err)
	}

	client, chainIDInt, err := dialChain(ctx, "")
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}
	defer client.Close()

	// Fetch authoritative merchantId/productId from CommissionEscrow.
	// The contract reads these from the escrow record and stores them in the on-chain Review;
	// the content hash preimage must use the same values or verifiers cannot reproduce the hash.
	callData, err := commissionEscrowABI.Pack("getEscrow", escrowID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("pack getEscrow: %w", err)
	}
	rawResult, err := client.CallContract(ctx, ethereum.CallMsg{To: &escrowAddr, Data: callData}, nil)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("getEscrow(%s): %w", in.EscrowID, err)
	}
	escrow, err := decodeGetEscrow(rawResult)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}
	merchantID, productID := escrow.MerchantID, escrow.ProductID

	if callerMerchantID.Cmp(merchantID) != 0 {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf(
			"merchant_id mismatch: supplied %s but escrow %s has merchantId %s",
			in.MerchantID, in.EscrowID, merchantID,
		)
	}
	if callerProductID != productID {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf(
			"product_id mismatch: supplied %s but escrow %s has productId 0x%x",
			in.ProductID, in.EscrowID, productID[:],
		)
	}

	contentHash, err := computeContentHash(agentID, merchantID, productID, in.ContentJSON)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("build transactor: %w", err)
	}

	contract := bind.NewBoundContract(registryAddr, reviewRegistryABI, client, client, client)

	tx, err := contract.Transact(auth, "publishReviewWithEscrowProof",
		agentID, contentHash, escrowID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("publishReviewWithEscrowProof tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("tx reverted: %s", tx.Hash().Hex())
	}

	reviewID, err := extractReviewID(receipt)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}

	return nil, publishEscrowReviewOutput{
		ReviewID: reviewID.String(),
		TxHash:   tx.Hash().Hex(),
	}, nil
}

// ── pay_for_product ────────────────────────────────────────────────────────────

type voteArg struct {
	ReviewID  int64  `json:"review_id"`
	Reasoning string `json:"reasoning"`
}

type payForProductInput struct {
	// Buyer agent ID (decimal string). Key is resolved via AGENT_KEYS or AGENT_PRIVATE_KEY.
	// Optional: omit for an agent-less purchase (no ERC-8004 identity yet) — the sentinel
	// buyer id is sent and the fallback AGENT_PRIVATE_KEY wallet pays (REF-134).
	AgentID string `json:"agent_id,omitempty"`
	// Full ref link URL returned by query_registry or fetch_review, e.g.
	// https://api.example/r/<base64url-token>. The token is decoded and verified locally.
	RefLink string `json:"ref_link"`
	// Optional inline votes (REF-143): 1–3 reviews that influenced this purchase. After the
	// purchase settles, the tool signs and submits these via the backend's cast_review_votes
	// two-step, before returning. Omit to skip voting (behaviour is then unchanged).
	SubmitVotes []voteArg `json:"submit_votes,omitempty"`
	// Owner-confirmed spending cap in USDC base units (REF-193). When set, the tool refuses if
	// the merchant's LIVE price exceeds it — so a price rise after an intent was queued cannot
	// overspend past the confirmed budget. The runner passes the intent payload's max_amount.
	// Omit for no cap (unchanged behaviour).
	MaxAmount string `json:"max_amount,omitempty"`
	// Idempotency key for at-most-once execution (REF-193). When set, the ERC-3009 nonce is
	// derived deterministically from (payer ‖ idempotency_key) instead of random, so a retry of
	// the SAME purchase reuses the nonce and the second receiveWithAuthorization reverts — the
	// wallet is charged at most once. The runner passes the intent_id. Omit for a random nonce.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type payForProductOutput struct {
	EscrowID string `json:"escrow_id"` // decimal string
	TxHash   string `json:"tx_hash"`
	// NextSteps is an advisory nudge (REF-131) pointing the buyer at cast_review_votes
	// for the reviews that influenced this purchase. The escrow_id the vote flow needs
	// is carried in EscrowID above; this is the human-readable prompt.
	NextSteps string `json:"next_steps"`
	// VotesRecorded is set when inline votes were submitted successfully (REF-143).
	VotesRecorded int `json:"votes_recorded,omitempty"`
	// VotesError is set when inline voting failed AFTER a successful payment — the purchase
	// still stands; the agent should retry votes via cast_review_votes with this escrow_id.
	VotesError string `json:"votes_error,omitempty"`
}

// validateVoteArgs mirrors the backend's cast_review_votes guards so an invalid inline vote
// fails fast, before payment. Empty/nil is valid (voting is optional).
func validateVoteArgs(v []voteArg) error {
	if len(v) == 0 {
		return nil
	}
	if len(v) > 3 {
		return fmt.Errorf("submit_votes: at most 3 votes, got %d", len(v))
	}
	for _, x := range v {
		if strings.TrimSpace(x.Reasoning) == "" {
			return fmt.Errorf("submit_votes: reasoning required for review_id %d", x.ReviewID)
		}
		if len([]rune(x.Reasoning)) > 280 {
			return fmt.Errorf("submit_votes: reasoning exceeds 280 chars for review_id %d", x.ReviewID)
		}
	}
	return nil
}

// payVoteReminder is the advisory next-step returned alongside a successful payment.
// Voting is deliberate, judgment-based, and a separate two-step signed flow on the
// referrer-agent server, so this only nudges — it never auto-calls cast_review_votes.
// The nudge deliberately states no obligation level: whether a vote is mandatory (the
// ≥5-reviews-returned case) lives in the agent runbook, not in a single tool's output.
const payVoteReminder = "If any reviews materially influenced this purchase, cast votes via " +
	"cast_review_votes (referrer-agent) using this escrow_id — allow a few seconds first for " +
	"the purchase to be indexed. Vote deliberately, only for the reviews that shaped your " +
	"decision; votes feed the platform's Review Rank."

// payBindReminder is the agent-less next step (REF-265 item 1). cast_review_votes REQUIRES
// agent_id, so the vote nudge is not merely premature there — it cannot be satisfied at all.
const payBindReminder = "This was an agent-less purchase, so no votes can be cast yet: " +
	"cast_review_votes requires an agent_id you do not have. Register an ERC-8004 identity, then " +
	"bind this escrow to it with bind_escrow (sent from the same wallet that paid) — that also " +
	"releases the held cashback and lets you publish the buyer review. Vote with " +
	"cast_review_votes afterwards, using this escrow_id."

// payNextSteps picks the advisory next step for a settled purchase.
func payNextSteps(agentLess bool) string {
	if agentLess {
		return payBindReminder
	}
	return payVoteReminder
}

// enforceMaxAmount refuses a purchase whose LIVE merchant price exceeds the
// owner-confirmed max_amount (REF-193 A). Both are USDC base-unit decimal
// strings. An empty max is "no cap" (back-compat for non-intent callers). This
// closes the gap where pay_for_product signed requirements.Amount verbatim: a
// price rising above the queued budget after the intent was confirmed would
// otherwise be authorized silently.
func enforceMaxAmount(live, max string) error {
	if strings.TrimSpace(max) == "" {
		return nil
	}
	liveBig, ok := new(big.Int).SetString(strings.TrimSpace(live), 10)
	if !ok {
		return fmt.Errorf("invalid live amount %q", live)
	}
	maxBig, ok := new(big.Int).SetString(strings.TrimSpace(max), 10)
	if !ok {
		return fmt.Errorf("invalid max_amount %q", max)
	}
	if liveBig.Cmp(maxBig) > 0 {
		return fmt.Errorf("live price %s exceeds approved max_amount %s", liveBig, maxBig)
	}
	return nil
}

// deriveNonce produces a DETERMINISTIC ERC-3009 nonce from the payer and an
// idempotency key (REF-193 B): keccak256(payer ‖ idempotency_key). Because
// ERC-3009 tracks used nonces per authorizer on-chain, replaying the same
// intent reuses the nonce, so the second receiveWithAuthorization reverts
// ("authorization used") — at-most-once, chain-enforced. Callers that pass no
// idempotency key keep the prior random-nonce behaviour.
func deriveNonce(payer common.Address, idempotencyKey string) [32]byte {
	h := crypto.Keccak256(append(payer.Bytes(), []byte(idempotencyKey)...))
	var n [32]byte
	copy(n[:], h)
	return n
}

func handlePayForProduct(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in payForProductInput,
) (*sdkmcp.CallToolResult, payForProductOutput, error) {
	// ── key + chain config ─────────────────────────────────────────────────────
	// Validate inline votes up front — fail before paying if they are malformed.
	if err := validateVoteArgs(in.SubmitVotes); err != nil {
		return nil, payForProductOutput{}, err
	}
	privKey, err := signerKeys.KeyFor(in.AgentID)
	if err != nil {
		return nil, payForProductOutput{}, err
	}
	buyerAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

	// Agent-less buyer (REF-134): an empty agent_id means "no ERC-8004 identity yet".
	// Pay with the fallback wallet key (resolved above) and send the sentinel buyer id
	// so the router skips the ownerOf bind and records the paying wallet for a later
	// deferred identity bind. A real agent_id is passed through unchanged.
	buyerAgentIDStr := buyerAgentIDOrSentinel(in.AgentID)
	if buyerAgentIDStr == sentinelBuyerAgentID && len(in.SubmitVotes) > 0 {
		return nil, payForProductOutput{}, fmt.Errorf("submit_votes requires an agent identity; an agent-less purchase (empty agent_id) cannot vote — bind an identity first, then cast_review_votes")
	}

	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, payForProductOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	chainIDStr := os.Getenv("CHAIN_ID")
	if chainIDStr == "" {
		chainIDStr = "84532"
	}
	chainIDInt, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("invalid CHAIN_ID: %w", err)
	}
	chainID := big.NewInt(chainIDInt)

	// ── parse ref link → api base + token ─────────────────────────────────────
	parsed, err := url.Parse(in.RefLink)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("invalid ref_link: %w", err)
	}
	apiBase := parsed.Scheme + "://" + parsed.Host
	parts := strings.SplitN(parsed.Path, "/r/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, payForProductOutput{}, fmt.Errorf("ref_link has no /r/<token> path: %s", in.RefLink)
	}
	urlChainSeg, attributionToken, err := splitRefPath(parts[1])
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("ref_link: %w", err)
	}
	// A chain-qualified link (<base>/r/<chainID>/<token>) naming a non-Base rail is
	// rejected up front — this edge path is Base-only. Base mints the bare form.
	if urlChainSeg != "" && urlChainSeg != chainIDStr {
		return nil, payForProductOutput{}, fmt.Errorf("ref_link is for chain %s, but this signer is configured for chain %s", urlChainSeg, chainIDStr)
	}

	// ── decode + verify the token locally (no resolution round-trip) ───────────
	// The token in the link IS the self-contained attribution token (base64url of
	// payload || Ed25519 sig). Fetch the attestation pubkey for OUR configured chain
	// (trusted, so an unverified token can't steer key selection), verify the token's
	// signature against it, then confirm the token was minted for this chain. All the
	// pay targets come straight from the decoded payload — REF-139 drops the backend
	// GET /r/<token> resolution entirely.
	//
	// Trust note: the attestation key is fetched from the ref link's own host. This is
	// no weaker than the resolution it replaces (which trusted that host's UNSIGNED
	// response); the signature check is strictly stronger. Pinning the well-known to a
	// configured trusted origin — so a link on an attacker host can't self-attest — is a
	// deferred onboarding-trust-model item (decision-edge-reflink-agentless-buy.md, TODO).
	httpClient := &http.Client{Timeout: 30 * time.Second}
	pubKeyHex, err := attestationPubKey(ctx, httpClient, apiBase, chainIDInt)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("fetch attestation key: %w", err)
	}
	tok, err := verifyAndDecodeToken(attributionToken, pubKeyHex)
	if err != nil {
		return nil, payForProductOutput{}, err
	}
	if tok.ChainID != chainIDInt {
		return nil, payForProductOutput{}, fmt.Errorf("attribution token is for chain %d, but this signer is configured for chain %d", tok.ChainID, chainIDInt)
	}
	merchantEndpoint := tok.MerchantEndpoint
	splitRouterAddr := tok.SplitRouter

	// ── phase 1: probe merchant for 402 payment requirements ──────────────────
	phase1Req, err := http.NewRequestWithContext(ctx, http.MethodPost, merchantEndpoint, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("build phase1 request: %w", err)
	}
	phase1Req.Header.Set("Content-Type", "application/json")
	phase1Req.Header.Set("X-Referrer-Token", attributionToken)
	phase1Req.Header.Set("X-Referrer-Buyer-Agent-Id", buyerAgentIDStr)
	phase1Resp, err := httpClient.Do(phase1Req)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("phase 1: %w", err)
	}
	defer phase1Resp.Body.Close()
	phase1Body, _ := io.ReadAll(phase1Resp.Body)
	if phase1Resp.StatusCode != http.StatusPaymentRequired {
		return nil, payForProductOutput{}, fmt.Errorf("phase 1: expected 402, got %d: %s", phase1Resp.StatusCode, phase1Body)
	}
	var payReq x402types.PaymentRequired
	if err := json.Unmarshal(phase1Body, &payReq); err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("parse payment requirements: %w", err)
	}
	if len(payReq.Accepts) == 0 {
		return nil, payForProductOutput{}, fmt.Errorf("payment requirements: no accepted payment methods")
	}
	requirements := payReq.Accepts[0]
	tokenAddr := requirements.Asset
	tokenName, _ := requirements.Extra["name"].(string)
	tokenVersion, _ := requirements.Extra["version"].(string)

	// Refuse before signing if the live price exceeds the owner-confirmed cap (REF-193 A).
	if err := enforceMaxAmount(requirements.Amount, in.MaxAmount); err != nil {
		return nil, payForProductOutput{}, err
	}

	// ── sign ERC-3009 authorization ────────────────────────────────────────────
	// Deterministic nonce when an idempotency key is supplied (REF-193 B) → a replayed intent
	// reuses the nonce and the second transfer reverts (at-most-once); random otherwise.
	var nonce32 [32]byte
	if strings.TrimSpace(in.IdempotencyKey) != "" {
		nonce32 = deriveNonce(crypto.PubkeyToAddress(privKey.PublicKey), in.IdempotencyKey)
	} else if _, err := rand.Read(nonce32[:]); err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("generate nonce: %w", err)
	}
	authz := evm.ExactEIP3009Authorization{
		From:        buyerAddr,
		To:          splitRouterAddr,
		Value:       requirements.Amount,
		ValidAfter:  "0",
		ValidBefore: strconv.FormatInt(time.Now().Add(5*time.Minute).Unix(), 10),
		Nonce:       "0x" + hex.EncodeToString(nonce32[:]),
	}
	// SplitRouter.route() calls receiveWithAuthorization, so this must be signed under the
	// ReceiveWithAuthorization typehash. TransferWithAuthorization has identical fields under a
	// different struct name and hashes differently, so real USDC rejects it inside the token
	// (REF-269). evm.HashEIP3009Authorization pins Transfer inline with no config path, which is
	// why it is no longer used here.
	erc3009Hash, err := hashERC3009Receive(authz, chainID, tokenAddr, tokenName, tokenVersion)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("hash erc3009: %w", err)
	}
	erc3009Sig, err := crypto.Sign(erc3009Hash, privKey)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("sign erc3009: %w", err)
	}
	erc3009Sig[64] += 27

	// ── build and encode x402 payment payload ──────────────────────────────────
	evmPayload := &evm.ExactEIP3009Payload{
		Signature:     "0x" + hex.EncodeToString(erc3009Sig),
		Authorization: authz,
	}
	paymentPayload := x402types.PaymentPayload{
		X402Version: 2,
		Payload:     evmPayload.ToMap(),
		Accepted:    requirements,
		Extensions: map[string]any{
			"attributionToken": attributionToken,
			"buyerAgentId":     buyerAgentIDStr,
		},
	}
	payloadJSON, err := json.Marshal(paymentPayload)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("marshal payment payload: %w", err)
	}
	paymentHeader := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// ── phase 2: submit payment ────────────────────────────────────────────────
	phase2Req, err := http.NewRequestWithContext(ctx, http.MethodPost, merchantEndpoint, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("build phase2 request: %w", err)
	}
	phase2Req.Header.Set("Content-Type", "application/json")
	phase2Req.Header.Set("PAYMENT-SIGNATURE", paymentHeader)
	phase2Client := &http.Client{Timeout: 90 * time.Second}
	phase2Resp, err := phase2Client.Do(phase2Req)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("phase 2: %w", err)
	}
	defer phase2Resp.Body.Close()
	phase2Body, _ := io.ReadAll(phase2Resp.Body)
	if phase2Resp.StatusCode != http.StatusOK {
		return nil, payForProductOutput{}, phase2Failure(phase2Resp.StatusCode, string(phase2Body))
	}
	var phase2Result map[string]any
	if err := json.Unmarshal(phase2Body, &phase2Result); err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("parse phase 2 response: %w", err)
	}
	txHashStr, _ := phase2Result["transaction"].(string)
	if txHashStr == "" {
		return nil, payForProductOutput{}, fmt.Errorf("phase 2 response missing 'transaction' field: %s", phase2Body)
	}

	// ── wait for receipt + extract escrow ID ───────────────────────────────────
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, _, err := client.TransactionByHash(waitCtx, common.HexToHash(txHashStr))
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("fetch tx %s: %w", txHashStr, err)
	}
	receipt, err := bind.WaitMined(waitCtx, client, tx)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, payForProductOutput{}, fmt.Errorf("tx reverted: %s", txHashStr)
	}

	escrowID, err := extractEscrowID(receipt)
	if err != nil {
		return nil, payForProductOutput{}, err
	}

	out := payForProductOutput{
		EscrowID:  escrowID.String(),
		TxHash:    txHashStr,
		NextSteps: payNextSteps(buyerAgentIDStr == sentinelBuyerAgentID),
	}
	if len(in.SubmitVotes) > 0 {
		// Payment has settled — cast the inline votes now. A vote failure must NOT fail the
		// whole call (the purchase already stands); report it so the agent can retry manually.
		mcpURL := os.Getenv("REFERRER_AGENT_MCP_URL")
		recorded, voteErr := castVotesViaBackend(ctx, mcpURL, agentIDInt(in.AgentID), escrowID.Int64(), in.SubmitVotes, privKey)
		if voteErr != nil {
			out.VotesError = voteErr.Error()
			out.NextSteps = "Payment succeeded but inline voting failed: " + voteErr.Error() +
				" — retry cast_review_votes (referrer-agent) with this escrow_id."
		} else {
			out.VotesRecorded = recorded
			out.NextSteps = fmt.Sprintf("Purchase settled and %d vote(s) recorded.", recorded)
		}
	}
	return nil, out, nil
}

// agentIDInt parses the tool's decimal agent_id; 0 on malformed input (keys resolve upstream).
func agentIDInt(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func extractEscrowID(receipt *types.Receipt) (*big.Int, error) {
	for _, log := range receipt.Logs {
		if len(log.Topics) >= 2 && log.Topics[0] == escrowDepositedTopic {
			return new(big.Int).SetBytes(log.Topics[1].Bytes()), nil
		}
	}
	return nil, fmt.Errorf("EscrowDeposited event not found in receipt")
}

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	srv := sdkmcp.NewServer(
		&sdkmcp.Implementation{Name: "referrer-signer", Version: "1"},
		nil,
	)

	ks, err := parseKeystore(os.Getenv("AGENT_KEYS"), os.Getenv("AGENT_PRIVATE_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer: key config:", err)
		os.Exit(1)
	}
	signerKeys = ks

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_review_commitment",
		Description: "Sign an EIP-712 ReviewCommitment using the agent's private key. " +
			"Call this between submit_admin_approved_review step 1 and step 2: " +
			"pass the 'commitment' object from submit_admin_approved_review step 1 exactly as returned, " +
			"then use the returned 'signature' as 'agent_sig' in submit_admin_approved_review step 2.",
	}, handleSign)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_vote_commitment",
		Description: "Sign an EIP-712 VoteCommitment using the agent's private key. " +
			"Call this between cast_review_votes step 1 and step 2: pass the 'commitment' object from " +
			"cast_review_votes step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in cast_review_votes step 2.",
	}, handleSignVote)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_cashback_rate_commitment",
		Description: "Sign an EIP-712 CashbackRateCommitment using the agent's private key. " +
			"Call this between set_default_cashback_rate step 1 and step 2: pass the 'commitment' object from " +
			"set_default_cashback_rate step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in set_default_cashback_rate step 2.",
	}, handleSignCashbackRate)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_telegram_link_commitment",
		Description: "Sign an EIP-712 TelegramLinkCommitment using the agent's owner private key. " +
			"Call this between link_telegram step 1 and step 2: pass the 'commitment' object from " +
			"link_telegram step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in link_telegram step 2 (with the same nonce and expiry).",
	}, handleSignTelegramLink)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_intent_access_commitment",
		Description: "Sign an EIP-712 IntentAccessCommitment using the agent's owner private key. " +
			"Call this between get_pending_intents step 1 and step 2: pass the 'commitment' object from " +
			"get_pending_intents step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in get_pending_intents step 2 (with the same nonce and expiry).",
	}, handleSignIntentAccess)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_intent_mark_commitment",
		Description: "Sign an EIP-712 IntentMarkCommitment using the agent's owner private key. " +
			"Call this between mark_intent_executed step 1 and step 2: pass the 'commitment' object from " +
			"mark_intent_executed step 1 exactly as returned (it binds intent_id and result), then use the " +
			"returned 'signature' as 'agent_sig' in mark_intent_executed step 2 (with the same intent_id, " +
			"result, nonce, and expiry).",
	}, handleSignIntentMark)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_intent_skip_commitment",
		Description: "Sign an EIP-712 IntentSkipCommitment using the agent's owner private key. " +
			"Call this between mark_intent_skipped step 1 and step 2: pass the 'commitment' object from " +
			"mark_intent_skipped step 1 exactly as returned (it binds intent_id and reason), then use the " +
			"returned 'signature' as 'agent_sig' in mark_intent_skipped step 2 (with the same intent_id, " +
			"reason, nonce, and expiry).",
	}, handleSignIntentSkip)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_charge_commitment",
		Description: "Sign an EIP-712 ChargeCommitment with the buyer (payer) wallet that made the " +
			"charge transfer and owns the buyer agent. Pass the charge tx hash ('txHash'), the " +
			"attribution token, the buyer agent id, the Base chain id ('chainId'), and the Base " +
			"SplitRouter address ('splitRouterAddr'); use the returned 'signature' as " +
			"'buyerSignature' in POST /mpp/charge. (REF-218: these are Base values, not Tempo — " +
			"the old 'tempoChainId'/'splitRouterMppAddr' field names are retired.)",
	}, handleSignCharge)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "publish_escrow_review",
		Description: "Submit a buyer review directly on-chain using an escrow purchase as proof. " +
			"Calls ReviewRegistry.publishReviewWithEscrowProof() with the agent's private key. " +
			"Use this after a purchase is confirmed (escrow deposited). " +
			"After this succeeds, call register_purchase_review on referrer-agent with the returned review_id.",
	}, handlePublishEscrowReview)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "bind_escrow",
		Description: "Bind an agent-less purchase's escrow to your ERC-8004 agent identity by sending " +
			"CommissionEscrow.bind(escrowId, agentId) on-chain with the agent's key, unlocking the deferred " +
			"cashback + enabling the deferred review. PRECONDITION: the signer key MUST be the exact wallet " +
			"that paid the agent-less purchase AND must already own agent_id (register the identity first). " +
			"Inputs: escrow_id (from pay_for_product / list_escrows), agent_id. After it succeeds, the backend " +
			"rebinds the purchase automatically; then cast_review_votes, publish_escrow_review, and register_purchase_review.",
	}, handleBindEscrow)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "trigger_settle_fallback",
		Description: "Force-settle an escrow the oracle never settled (CommissionEscrow.triggerSettleFallback). " +
			"Permissionless — any agent may call it — and it opens 10 days after the escrow's windowEnd (~day 70). " +
			"Check fallback_available via get_escrow_status (referrer-agent) first, but note its day-70 timing is " +
			"derived from the DB confirmation date, not this contract's windowEnd, so on a non-default settlement " +
			"window it can be wrong; this tool reads windowEnd itself and refuses with the real date, so calling it " +
			"and reading a refusal costs only the RPC call. list_escrows always reports fallback_available false. " +
			"This is NOT a claim and it does not pay you: the held-back commission goes to the protocol TREASURY (so a " +
			"reviewer calling this forfeits what a normal day-60 settle would have paid it), any unreleased cashback goes " +
			"to the REVIEWER's wallet (the buyer never published its review, so the cashback reverts to its funder), and " +
			"you pay the gas. Call it to unstick funds after an oracle failure, not to get paid.",
	}, handleTriggerSettleFallback)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "update_review_content_onchain",
		Description: "Edit a buyer review's content on-chain within its 7-day window " +
			"(ReviewRegistry.updateReviewContent). This is the FIRST of two calls: it updates only the " +
			"on-chain content hash. Afterwards you MUST call update_review_content (referrer-agent) with " +
			"the same review_id and the SAME content_json to sync the stored text and re-run the alignment " +
			"oracle — that tool verifies your content against the hash this one stored and rejects any " +
			"difference. Pass review_id (the ON-CHAIN id) and the full replacement content_json; the tool " +
			"reads the review from the chain to build the hash and to pick the signing key, so do not pass " +
			"agent/merchant/product ids. Only a buyer review published with an escrow proof is editable, " +
			"and only by the reviewer agent's owner or its registered agent wallet. IMPORTANT: this tool " +
			"only checks that content_json is valid JSON — it does NOT validate it against the product's " +
			"content schema. Call get_review_schema (referrer-agent) for the product's category and check " +
			"your replacement content against it BEFORE calling this: content that fails that schema (e.g. " +
			"a missing rating, or a description with '<'/'>') still lands on-chain here, and " +
			"update_review_content will then refuse it permanently — leaving the review's stored text and " +
			"its on-chain hash disagreeing until you edit again within the window.",
	}, handleUpdateReviewContentOnchain)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "set_product_commission",
		Description: "Change the commission rate a merchant pays referrers for one product " +
			"(ProductRegistry.setCommission), sent on-chain with the merchant's own key. merchant_id is " +
			"the merchant's ERC-8004 agent id and product_id is the on-chain bytes32 (0x-prefixed, 32 " +
			"bytes) — not a slug. commission_bps is 0-10000, where 1000 = 10%. IMPORTANT: the new rate is " +
			"read LIVE by SplitRouter at settlement, so it applies to every purchase that settles after " +
			"this call, including ref links already issued and payments already authorised under the old " +
			"rate. Nothing on-chain locks the previous rate. The signer key must own merchant_id or hold " +
			"COMMISSION_MANAGER for it; that role is separate from PRODUCT_MANAGER, so a key that can add " +
			"products cannot necessarily reprice them.",
	}, handleSetProductCommission)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "set_product_active",
		Description: "List or delist one of a merchant's products (ProductRegistry.setProductActive), " +
			"sent on-chain with the merchant's own key. Pass active=true to accept new purchases and ref " +
			"links for it, active=false to stop them; the field is required, so a call that omits it fails " +
			"rather than delisting. merchant_id is the merchant's ERC-8004 agent id and product_id is the " +
			"on-chain bytes32. Delisting does not touch existing escrows or published reviews, and does not " +
			"remove the product — set it active again to relist. The signer key must own merchant_id or " +
			"hold PRODUCT_MANAGER for it.",
	}, handleSetProductActive)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "pay_for_product",
		Description: "Complete an x402 buyer payment for a product via a referral link. " +
			"Decodes the self-contained ref link locally — verifying its Ed25519 signature against the " +
			"protocol attestation key published at /.well-known/referrer-agent (cached), with NO backend " +
			"resolution round-trip — to read the merchant endpoint, settlement router, and chain straight " +
			"from the token. Probes the merchant for payment requirements (402), signs an ERC-3009 " +
			"authorization, submits the payment, and waits for the on-chain EscrowDeposited event. " +
			"Returns escrow_id and tx_hash. Use the escrow_id with publish_escrow_review afterward. " +
			"Omit agent_id to buy agent-less (no ERC-8004 identity yet): the buyer wallet is recorded " +
			"on-chain for a later identity bind, and cashback is held until then. Agent-less purchases " +
			"cannot submit_votes (bind an identity first). " +
			"Optionally pass submit_votes (1–3 {review_id, reasoning}) to cast the buyer's votes in the " +
			"same call: after settlement the tool signs and submits them via the backend's cast_review_votes " +
			"two-step (retrying past indexer lag), returning votes_recorded. Omit submit_votes to skip voting. " +
			"A vote failure never voids the payment — votes_error is set and the purchase still stands. " +
			"Inline voting requires REFERRER_AGENT_MCP_URL to point at the referrer-agent MCP endpoint. " +
			"The next_steps field is advisory and depends on the path: cast_review_votes for an " +
			"agent-bound purchase, bind_escrow for an agent-less one (which cannot vote until bound). " +
			"A retry whose idempotency_key was already used fails with an error prefixed " +
			"\"already_paid:\" — the wallet was charged at most once, so treat the purchase as complete " +
			"and mark the intent executed rather than retrying.",
	}, handlePayForProduct)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &sdkmcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer:", err)
		os.Exit(1)
	}
}
