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

// ── OpenSessionCommitment EIP-712 (must match backend signing/open_session.go exactly) ──

const openSessionCommitmentTypeString = "OpenSessionCommitment(address payer,bytes32 salt,uint256 buyerAgentId,bytes32 attributionTokenHash)"

var openSessionCommitmentTypehash = crypto.Keccak256Hash([]byte(openSessionCommitmentTypeString))

type openSessionCommitmentMessage struct {
	Payer                string `json:"payer"`
	Salt                 string `json:"salt"`
	BuyerAgentID         string `json:"buyerAgentId"`
	AttributionTokenHash string `json:"attributionTokenHash"`
}

type openSessionCommitmentPayload struct {
	// Types/PrimaryType are accepted (eth_signTypedData_v4 envelope) but unused — the digest is
	// recomputed from Domain + Message.
	Types       map[string]any               `json:"types,omitempty"`
	PrimaryType string                       `json:"primaryType,omitempty"`
	Domain      commitmentDomain             `json:"domain"`
	Message     openSessionCommitmentMessage `json:"message"`
}

type signOpenSessionInput struct {
	Commitment openSessionCommitmentPayload `json:"commitment"`
}

// computeOpenSessionDigest mirrors backend signing.OpenSessionDigest exactly.
func computeOpenSessionDigest(p openSessionCommitmentPayload) ([]byte, error) {
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

	payer := common.HexToAddress(p.Message.Payer)
	salt, err := hexToBytes32(p.Message.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}
	tokenHash, err := hexToBytes32(p.Message.AttributionTokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid attributionTokenHash: %w", err)
	}
	buyerAgentID, ok := new(big.Int).SetString(p.Message.BuyerAgentID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid buyerAgentId: %q", p.Message.BuyerAgentID)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiAddress}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiBytes32},
	}.Pack(
		openSessionCommitmentTypehash, payer, salt, buyerAgentID, tokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

// handleSignOpenSession signs an OpenSessionCommitment with the buyer-agent owner's (= payer) key.
func handleSignOpenSession(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signOpenSessionInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.BuyerAgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	// The channel payer must be the buyer-agent owner; the backend verifies ecrecover == payer.
	// Fail locally with a clear message if the resolved key isn't the payer.
	payer := common.HexToAddress(in.Commitment.Message.Payer)
	if addr := crypto.PubkeyToAddress(privKey.PublicKey); addr != payer {
		return nil, signOutput{}, fmt.Errorf(
			"signing key %s does not match payer %s for buyer agent %s", addr.Hex(), payer.Hex(), in.Commitment.Message.BuyerAgentID)
	}

	digest, err := computeOpenSessionDigest(in.Commitment)
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
