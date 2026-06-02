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

	reviewPublishedTopic  = crypto.Keccak256Hash([]byte("ReviewPublished(uint256,uint256,uint256,bytes32,bytes32,uint8,uint40)"))
	escrowDepositedTopic  = crypto.Keccak256Hash([]byte("EscrowDeposited(uint256,uint256,uint256,uint256,uint256,bytes32,uint128,uint128)"))

	abiUint256 = mustABIType("uint256")
	abiBytes32 = mustABIType("bytes32")
	abiAddress = mustABIType("address")
	abiString  = mustABIType("string")

	reviewRegistryABI = mustParseABI(`[
		{"inputs":[{"name":"agentId","type":"uint256"},{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"contentHash","type":"bytes32"},{"name":"escrowId","type":"uint256"}],"name":"publishReviewWithEscrowProof","outputs":[{"name":"reviewId","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
		{"anonymous":false,"inputs":[{"indexed":true,"name":"reviewId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"merchantId","type":"uint256"},{"indexed":false,"name":"productId","type":"bytes32"},{"indexed":false,"name":"contentHash","type":"bytes32"},{"indexed":false,"name":"proofType","type":"uint8"},{"indexed":false,"name":"timestamp","type":"uint40"}],"name":"ReviewPublished","type":"event"}
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
	Domain  commitmentDomain  `json:"domain"`
	Message commitmentMessage `json:"message"`
}

// ── sign_review_commitment ─────────────────────────────────────────────────────

type signInput struct {
	Commitment reviewCommitmentPayload `json:"commitment"`
}

type signOutput struct {
	// 0x-prefixed 65-byte hex signature. Pass directly as agent_sig in submit_review step 2.
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
	Domain  commitmentDomain     `json:"domain"`
	Message voteCommitmentMessage `json:"message"`
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
	merchantID, ok := new(big.Int).SetString(in.MerchantID, 10)
	if !ok {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid merchant_id: %q", in.MerchantID)
	}
	escrowID, ok := new(big.Int).SetString(in.EscrowID, 10)
	if !ok {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid escrow_id: %q", in.EscrowID)
	}
	productID, err := hexToBytes32(in.ProductID)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid product_id: %w", err)
	}

	contentHash, err := computeContentHash(agentID, merchantID, productID, in.ContentJSON)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, err
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("build transactor: %w", err)
	}

	registryAddr := common.HexToAddress(registryAddrHex)
	contract := bind.NewBoundContract(registryAddr, reviewRegistryABI, client, client, client)

	tx, err := contract.Transact(auth, "publishReviewWithEscrowProof",
		agentID, merchantID, productID, contentHash, escrowID)
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

type payForProductInput struct {
	// Buyer agent ID (decimal string). Key is resolved via AGENT_KEYS or AGENT_PRIVATE_KEY.
	AgentID string `json:"agent_id"`
	// Full ref link URL returned by query_registry or fetch_review, e.g. http://localhost:8080/r/abc123
	RefLink string `json:"ref_link"`
}

type payForProductOutput struct {
	EscrowID string `json:"escrow_id"` // decimal string
	TxHash   string `json:"tx_hash"`
}

func handlePayForProduct(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in payForProductInput,
) (*sdkmcp.CallToolResult, payForProductOutput, error) {
	// ── key + chain config ─────────────────────────────────────────────────────
	privKey, err := signerKeys.KeyFor(in.AgentID)
	if err != nil {
		return nil, payForProductOutput{}, err
	}
	buyerAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

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
	token := parts[1]

	// ── resolve ref link ───────────────────────────────────────────────────────
	httpClient := &http.Client{Timeout: 30 * time.Second}
	refResp, err := httpClient.Get(apiBase + "/r/" + token)
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("resolve ref link: %w", err)
	}
	defer refResp.Body.Close()
	refBody, _ := io.ReadAll(refResp.Body)
	if refResp.StatusCode != http.StatusOK {
		return nil, payForProductOutput{}, fmt.Errorf("resolve ref link: HTTP %d: %s", refResp.StatusCode, refBody)
	}
	var refData map[string]any
	if err := json.Unmarshal(refBody, &refData); err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("parse ref link response: %w", err)
	}
	merchantEndpoint, _ := refData["merchantEndpoint"].(string)
	attributionToken, _ := refData["attributionToken"].(string)
	splitRouterAddr, _ := refData["splitRouterAddr"].(string)
	if merchantEndpoint == "" || attributionToken == "" || splitRouterAddr == "" {
		return nil, payForProductOutput{}, fmt.Errorf("ref link response missing fields: %s", refBody)
	}

	// ── phase 1: probe merchant for 402 payment requirements ──────────────────
	phase1Req, err := http.NewRequestWithContext(ctx, http.MethodPost, merchantEndpoint, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, payForProductOutput{}, fmt.Errorf("build phase1 request: %w", err)
	}
	phase1Req.Header.Set("Content-Type", "application/json")
	phase1Req.Header.Set("X-Referrer-Token", attributionToken)
	phase1Req.Header.Set("X-Referrer-Buyer-Agent-Id", in.AgentID)
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
			"buyerAgentId":     in.AgentID,
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

	return nil, payForProductOutput{
		EscrowID: escrowID.String(),
		TxHash:   txHashStr,
	}, nil
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
			"Call this between submit_review step 1 and step 2: " +
			"pass the 'commitment' object from submit_review step 1 exactly as returned, " +
			"then use the returned 'signature' as 'agent_sig' in submit_review step 2.",
	}, handleSign)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_vote_commitment",
		Description: "Sign an EIP-712 VoteCommitment using the agent's private key. " +
			"Call this between submit_votes step 1 and step 2: pass the 'commitment' object from " +
			"submit_votes step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in submit_votes step 2.",
	}, handleSignVote)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "publish_escrow_review",
		Description: "Submit a buyer review directly on-chain using an escrow purchase as proof. " +
			"Calls ReviewRegistry.publishReviewWithEscrowProof() with the agent's private key. " +
			"Use this after a purchase is confirmed (escrow deposited). " +
			"After this succeeds, call register_published_review on referrer-agent with the returned review_id.",
	}, handlePublishEscrowReview)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "pay_for_product",
		Description: "Complete an x402 buyer payment for a product via a referral link. " +
			"Resolves the ref link to find the merchant endpoint and attribution token, " +
			"probes the merchant for payment requirements (402), signs an ERC-3009 authorization, " +
			"submits the payment, and waits for the on-chain EscrowDeposited event. " +
			"Returns escrow_id and tx_hash. Use the escrow_id with publish_escrow_review afterward.",
	}, handlePayForProduct)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &sdkmcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer:", err)
		os.Exit(1)
	}
}
