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

// IntentMarkCommitment EIP-712 — must match backend signing/intent_mark_commitment.go exactly.
// Dedicated type binds the specific intentId + result being recorded, so a mark signature cannot be
// replayed against a different intent or to record a forged result, nor reused as a read (IntentAccess).
const intentMarkCommitmentTypeString = "IntentMarkCommitment(uint256 agentId,string intentId,string result,bytes32 nonce,uint256 expiry)"

var intentMarkCommitmentTypehash = crypto.Keccak256Hash([]byte(intentMarkCommitmentTypeString))

const intentMarkDomainName = "ReferrerIntentAccess" // documentation-only; digest reads domain verbatim

type intentMarkCommitmentMessage struct {
	AgentID  string `json:"agentId"`
	IntentID string `json:"intentId"`
	Result   string `json:"result"`
	Nonce    string `json:"nonce"`
	Expiry   string `json:"expiry"`
}

type intentMarkCommitmentPayload struct {
	Types       map[string]any              `json:"types,omitempty"`
	PrimaryType string                      `json:"primaryType,omitempty"`
	Domain      commitmentDomain            `json:"domain"`
	Message     intentMarkCommitmentMessage `json:"message"`
}

type signIntentMarkInput struct {
	Commitment intentMarkCommitmentPayload `json:"commitment"`
}

func computeIntentMarkDigest(p intentMarkCommitmentPayload) ([]byte, error) {
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

	// intentId + result are EIP-712 string members: each contributes keccak256(bytes(value))
	// packed as bytes32, in the order agentId, intentId, result, nonce, expiry.
	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiUint256}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256},
	}.Pack(
		intentMarkCommitmentTypehash,
		agentID,
		crypto.Keccak256Hash([]byte(p.Message.IntentID)),
		crypto.Keccak256Hash([]byte(p.Message.Result)),
		nonce,
		expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignIntentMark(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in signIntentMarkInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	if err := pinDomain(ctx, in.Commitment.Domain, specIntentMark); err != nil {
		return nil, signOutput{}, err
	}
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}
	digest, err := computeIntentMarkDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}
