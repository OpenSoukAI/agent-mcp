package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── EIP-712 type strings (must match ReviewRegistry contract exactly) ──────────

const (
	domainTypeString = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	commitmentTypeString = "ReviewCommitment(uint256 agentId,uint256 merchantId,bytes32 productId,bytes32 contentHash,uint256 nonce,uint256 expiry)"
)

var (
	domainTypehash     = crypto.Keccak256Hash([]byte(domainTypeString))
	commitmentTypehash = crypto.Keccak256Hash([]byte(commitmentTypeString))

	abiUint256 = mustABIType("uint256")
	abiBytes32 = mustABIType("bytes32")
	abiAddress = mustABIType("address")
)

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(fmt.Sprintf("abi.NewType(%q): %v", t, err))
	}
	return typ
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

// ── Tool input/output ──────────────────────────────────────────────────────────

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

// ── Tool handler ───────────────────────────────────────────────────────────────

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

	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx, &sdkmcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "referrer-signer:", err)
		os.Exit(1)
	}
}
