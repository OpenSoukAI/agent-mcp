package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// IntentSkipCommitment EIP-712 — must match backend signing/intent_skip_commitment.go exactly.
// Dedicated type binds the specific intentId + reason being recorded, so a skip signature cannot be
// replayed against a different intent or to record a forged reason, nor reused as a mark/read.
const intentSkipCommitmentTypeString = "IntentSkipCommitment(uint256 agentId,string intentId,string reason,bytes32 nonce,uint256 expiry)"

var intentSkipCommitmentTypehash = crypto.Keccak256Hash([]byte(intentSkipCommitmentTypeString))

const intentSkipDomainName = "ReferrerIntentAccess" // documentation-only; digest reads domain verbatim

type intentSkipCommitmentMessage struct {
	AgentID  string `json:"agentId"`
	IntentID string `json:"intentId"`
	Reason   string `json:"reason"`
	Nonce    string `json:"nonce"`
	Expiry   string `json:"expiry"`
}

type intentSkipCommitmentPayload struct {
	Types       map[string]any              `json:"types,omitempty"`
	PrimaryType string                      `json:"primaryType,omitempty"`
	Domain      commitmentDomain            `json:"domain"`
	Message     intentSkipCommitmentMessage `json:"message"`
}

type signIntentSkipInput struct {
	Commitment intentSkipCommitmentPayload `json:"commitment"`
}

func computeIntentSkipDigest(p intentSkipCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiAddress},
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
	nonce, err := hexToBytes32(p.Message.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}

	// intentId + reason are EIP-712 string members: each contributes keccak256(bytes(value)) packed
	// as bytes32, in the order agentId, intentId, reason, nonce, expiry.
	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiUint256}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256},
	}.Pack(
		intentSkipCommitmentTypehash,
		agentID,
		crypto.Keccak256Hash([]byte(p.Message.IntentID)),
		crypto.Keccak256Hash([]byte(p.Message.Reason)),
		nonce,
		expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignIntentSkip(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in signIntentSkipInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	if err := pinDomain(ctx, in.Commitment.Domain, specIntentSkip); err != nil {
		return nil, signOutput{}, err
	}
	keySigner, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}
	digest, err := computeIntentSkipDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}
	sig, err := keySigner.SignDigest(ctx, common.BytesToHash(digest))
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}
