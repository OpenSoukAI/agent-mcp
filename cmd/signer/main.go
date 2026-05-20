package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
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

func handleSign(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	keyHex := os.Getenv("AGENT_PRIVATE_KEY")
	if keyHex == "" {
		return nil, signOutput{}, fmt.Errorf("AGENT_PRIVATE_KEY env var not set")
	}

	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("invalid AGENT_PRIVATE_KEY: %w", err)
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
	keyHex := os.Getenv("AGENT_PRIVATE_KEY")
	if keyHex == "" {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("AGENT_PRIVATE_KEY env var not set")
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

	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	if err != nil {
		return nil, publishEscrowReviewOutput{}, fmt.Errorf("invalid AGENT_PRIVATE_KEY: %w", err)
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

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	srv := sdkmcp.NewServer(
		&sdkmcp.Implementation{Name: "referrer-signer", Version: "1"},
		nil,
	)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_review_commitment",
		Description: "Sign an EIP-712 ReviewCommitment using the agent's private key. " +
			"Call this between submit_review step 1 and step 2: " +
			"pass the 'commitment' object from submit_review step 1 exactly as returned, " +
			"then use the returned 'signature' as 'agent_sig' in submit_review step 2.",
	}, handleSign)

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "publish_escrow_review",
		Description: "Submit a buyer review directly on-chain using an escrow purchase as proof. " +
			"Calls ReviewRegistry.publishReviewWithEscrowProof() with the agent's private key. " +
			"Use this after a purchase is confirmed (escrow deposited). " +
			"After this succeeds, call register_published_review on referrer-agent with the returned review_id.",
	}, handlePublishEscrowReview)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &sdkmcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer:", err)
		os.Exit(1)
	}
}
