package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── ChargeCommitment EIP-712 (must match backend signing/charge_commitment.go exactly) ──

const chargeCommitmentTypeString = "ChargeCommitment(address payer,bytes32 paymentRef,uint256 buyerAgentId,bytes32 attributionTokenHash)"

var chargeCommitmentTypehash = crypto.Keccak256Hash([]byte(chargeCommitmentTypeString))

const chargeDomainName = "ReferrerMPPCharge"

type signChargeInput struct {
	TxHash           string `json:"txHash"`           // 0x-prefixed 32-byte charge tx hash (= paymentRef)
	AttributionToken string `json:"attributionToken"` // base64url signed attribution token
	BuyerAgentID     string `json:"buyerAgentId"`     // buyer agent NFT id (decimal)
	ChainID          int64  `json:"chainId"`          // EIP-712 domain chainId (Base)
	SplitRouterAddr  string `json:"splitRouterAddr"`  // EIP-712 domain verifyingContract (Base SplitRouter)
}

// computeChargeDigest mirrors backend signing.ChargeDigest exactly.
func computeChargeDigest(payer common.Address, paymentRef [32]byte, buyerAgentID *big.Int, attributionTokenHash [32]byte, chainID int64, verifyingContract common.Address) ([]byte, error) {
	if buyerAgentID == nil { // mirror backend orZero — never nil in this caller, defensive parity
		buyerAgentID = new(big.Int)
	}
	domainPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(chargeDomainName)),
		crypto.Keccak256Hash([]byte("1")),
		big.NewInt(chainID),
		verifyingContract,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiAddress}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiBytes32},
	}.Pack(
		chargeCommitmentTypehash, payer, paymentRef, buyerAgentID, attributionTokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

// handleSignCharge signs a ChargeCommitment with the buyer-agent owner's (= payer) key. The buyer
// is both the transfer sender and the agent owner; POST /mpp/charge recovers this signature and
// requires it == the on-chain transfer sender (REF-91).
func handleSignCharge(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in signChargeInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	// REF-218: chainId/splitRouterAddr are MCP tool inputs, supplied by the caller — not values the
	// backend sends. A zero chainId or empty/zero splitRouterAddr silently digests to a wrong
	// signer (chainId=0 or verifyingContract=0x0..0), which fails at recover with no diagnostic
	// pointing at the cause. Reject both loudly here instead, and name the old field names
	// explicitly since a caller still on tempoChainId/splitRouterMppAddr would otherwise land
	// exactly in that silent-zero trap.
	if in.ChainID == 0 {
		return nil, signOutput{}, fmt.Errorf(
			"chainId is required and must be nonzero (Base chainId — e.g. 84532 for Base Sepolia). " +
				"If you're passing the old field name 'tempoChainId', rename it to 'chainId'.")
	}
	if in.SplitRouterAddr == "" || common.HexToAddress(in.SplitRouterAddr) == (common.Address{}) {
		return nil, signOutput{}, fmt.Errorf(
			"splitRouterAddr is required and must be a nonzero address (the Base SplitRouter contract). " +
				"If you're passing the old field name 'splitRouterMppAddr', rename it to 'splitRouterAddr'.")
	}

	if err := pinDomain(ctx, commitmentDomain{
		Name: chargeDomainName, Version: "1", ChainID: in.ChainID, VerifyingContract: in.SplitRouterAddr,
	}, specCharge); err != nil {
		return nil, signOutput{}, err
	}
	privKey, err := signerKeys.KeyFor(in.BuyerAgentID)
	if err != nil {
		return nil, signOutput{}, err
	}
	payer := crypto.PubkeyToAddress(privKey.PublicKey)

	ref, err := hexToBytes32(in.TxHash)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("invalid txHash: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(in.AttributionToken)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("invalid attributionToken: %w", err)
	}
	tokenHash := crypto.Keccak256Hash(raw)
	buyerAgentID, ok := new(big.Int).SetString(in.BuyerAgentID, 10)
	if !ok {
		return nil, signOutput{}, fmt.Errorf("invalid buyerAgentId: %q", in.BuyerAgentID)
	}

	digest, err := computeChargeDigest(payer, ref, buyerAgentID, tokenHash, in.ChainID, common.HexToAddress(in.SplitRouterAddr))
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
