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

// ── TelegramLinkCommitment EIP-712 (must match backend signing/telegram_link_commitment.go exactly) ──
// Dedicated type + domain name so a telegram-link authorization can never be replayed as any other
// commitment. Mirrors CashbackRateCommitment field-for-field, MINUS the uint16 cashbackOfCommissionBps.
const telegramLinkCommitmentTypeString = "TelegramLinkCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"

var telegramLinkCommitmentTypehash = crypto.Keccak256Hash([]byte(telegramLinkCommitmentTypeString))

// telegramLinkDomainName documents the expected domain name (backend: "ReferrerTelegramLink").
// Like cashbackRateDomainName it is documentation-only and intentionally unreferenced — the digest
// reads the domain verbatim from the commitment payload the agent passes in.
const telegramLinkDomainName = "ReferrerTelegramLink"

type telegramLinkCommitmentMessage struct {
	AgentID string `json:"agentId"`
	Nonce   string `json:"nonce"`
	Expiry  string `json:"expiry"`
}

type telegramLinkCommitmentPayload struct {
	// Types and PrimaryType are part of the EIP-712 envelope — accepted but ignored.
	Types       map[string]any                `json:"types,omitempty"`
	PrimaryType string                        `json:"primaryType,omitempty"`
	Domain      commitmentDomain              `json:"domain"`
	Message     telegramLinkCommitmentMessage `json:"message"`
}

type signTelegramLinkInput struct {
	Commitment telegramLinkCommitmentPayload `json:"commitment"`
}

func computeTelegramLinkDigest(p telegramLinkCommitmentPayload) ([]byte, error) {
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
	nonce, err := hexToBytes32(p.Message.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiBytes32},
		{Type: abiUint256},
	}.Pack(
		telegramLinkCommitmentTypehash,
		agentID, nonce, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignTelegramLink(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signTelegramLinkInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	digest, err := computeTelegramLinkDigest(in.Commitment)
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
