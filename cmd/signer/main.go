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

	reviewPublishedTopic = crypto.Keccak256Hash([]byte("ReviewPublished(uint256,uint256,uint256,bytes32,bytes32,uint8,uint40)"))
	escrowDepositedTopic = crypto.Keccak256Hash([]byte("EscrowDeposited(uint256,uint256,uint256,address,uint256,uint256,bytes32,uint128,uint128)"))

	abiUint256 = mustABIType("uint256")
	abiBytes32 = mustABIType("bytes32")
	abiAddress = mustABIType("address")
	abiString  = mustABIType("string")

	reviewRegistryABI = mustParseABI(`[
		{"inputs":[{"name":"agentId","type":"uint256"},{"name":"contentHash","type":"bytes32"},{"name":"escrowId","type":"uint256"}],"name":"publishReviewWithEscrowProof","outputs":[{"name":"reviewId","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"reviewId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"merchantId","type":"uint256"},{"indexed":false,"name":"productId","type":"bytes32"},{"indexed":false,"name":"contentHash","type":"bytes32"},{"indexed":false,"name":"proofType","type":"uint8"},{"indexed":false,"name":"timestamp","type":"uint40"}],"name":"ReviewPublished","type":"event"}
	]`)

	commissionEscrowABI = mustParseABI(`[
		{"inputs":[{"name":"escrowId","type":"uint256"}],"name":"getEscrow","outputs":[{"components":[{"name":"reviewerAgentId","type":"uint256"},{"name":"buyerAgentId","type":"uint256"},{"name":"buyerWallet","type":"address"},{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"heldBackAmt","type":"uint128"},{"name":"cashbackAmt","type":"uint128"},{"name":"originalPurchaseAmt","type":"uint128"},{"name":"depositTimestamp","type":"uint40"},{"name":"windowEnd","type":"uint40"},{"name":"productType","type":"uint8"},{"name":"state","type":"uint8"},{"name":"cashbackReleased","type":"bool"}],"name":"","type":"tuple"}],"stateMutability":"view","type":"function"},
		{"inputs":[{"name":"escrowId","type":"uint256"},{"name":"agentId","type":"uint256"}],"name":"bind","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"escrowId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"boundBy","type":"address"}],"name":"EscrowBound","type":"event"}
	]`)
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
	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	registryAddrHex := os.Getenv("REVIEW_REGISTRY_ADDRESS")
	if registryAddrHex == "" {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("REVIEW_REGISTRY_ADDRESS env var not set")
	}
	escrowAddrHex := os.Getenv("COMMISSION_ESCROW_ADDRESS")
	if escrowAddrHex == "" {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("COMMISSION_ESCROW_ADDRESS env var not set")
	}

	chainIDStr := os.Getenv("CHAIN_ID")
	if chainIDStr == "" {
		chainIDStr = "84532" // Base Sepolia
	}
	chainIDInt, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid CHAIN_ID: %w", err)
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

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	// Fetch authoritative merchantId/productId from CommissionEscrow.
	// The contract reads these from the escrow record and stores them in the on-chain Review;
	// the content hash preimage must use the same values or verifiers cannot reproduce the hash.
	escrowAddr := common.HexToAddress(escrowAddrHex)
	callData, err := commissionEscrowABI.Pack("getEscrow", escrowID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("pack getEscrow: %w", err)
	}
	rawResult, err := client.CallContract(ctx, ethereum.CallMsg{To: &escrowAddr, Data: callData}, nil)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("getEscrow(%s): %w", in.EscrowID, err)
	}
	// ABI layout: (uint256 reviewerAgentId, uint256 buyerAgentId, address buyerWallet, uint256 merchantId, bytes32 productId, ...)
	// All static types; each slot is 32 bytes (address is left-padded to 32 bytes).
	if len(rawResult) < 160 {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("getEscrow returned short data: %d bytes", len(rawResult))
	}
	merchantID := new(big.Int).SetBytes(rawResult[96:128])
	var productID [32]byte
	copy(productID[:], rawResult[128:160])

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

	registryAddr := common.HexToAddress(registryAddrHex)
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

	// ── sign ERC-3009 authorization ────────────────────────────────────────────
	var nonce32 [32]byte
	if _, err := rand.Read(nonce32[:]); err != nil {
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
	erc3009Hash, err := evm.HashEIP3009Authorization(authz, chainID, tokenAddr, tokenName, tokenVersion)
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
		return nil, payForProductOutput{}, fmt.Errorf("phase 2: expected 200, got %d: %s", phase2Resp.StatusCode, phase2Body)
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
		NextSteps: payVoteReminder,
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
		Name: "sign_open_session_commitment",
		Description: "Sign an EIP-712 OpenSessionCommitment using the payer wallet (the buyer agent's owner key). " +
			"Call this between open_mpp_session step 1 and step 2: pass the 'commitment' object from " +
			"open_mpp_session step 1 exactly as returned, then use the returned 'signature' as 'payer_sig' " +
			"in open_mpp_session step 2.",
	}, handleSignOpenSession)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_charge_commitment",
		Description: "Sign an EIP-712 ChargeCommitment with the buyer (payer) wallet that made the " +
			"tempo/charge transfer and owns the buyer agent. Pass the charge tx hash ('txHash'), the " +
			"attribution token, the buyer agent id, the Tempo chain id ('tempoChainId'), and the " +
			"SplitRouterMPP address ('splitRouterMppAddr'); use the returned 'signature' as " +
			"'buyerSignature' in POST /mpp/charge.",
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
			"The next_steps field is an advisory reminder to cast_review_votes on reviews that influenced the purchase.",
	}, handlePayForProduct)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &sdkmcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer:", err)
		os.Exit(1)
	}
}
