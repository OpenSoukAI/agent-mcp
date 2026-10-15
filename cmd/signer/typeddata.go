package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
)

// EIP-712 typed data for everything the signer signs, so a policy backend receives the structure
// rather than an opaque digest. Values are JSON-friendly: integers as decimal strings, bytes32 and
// addresses as 0x-hex. The hand-rolled compute*Digest encoders stay as the independent check
// signTyped runs before every signature.

var eip712DomainType = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
	{Name: "chainId", Type: "uint256"},
	{Name: "verifyingContract", Type: "address"},
}

type tdField struct {
	name, typ string
	value     any
}

func typedData(primary, name, version string, chainID *big.Int, verifying string, fields []tdField) apitypes.TypedData {
	types := make([]apitypes.Type, len(fields))
	msg := make(apitypes.TypedDataMessage, len(fields))
	for i, f := range fields {
		types[i] = apitypes.Type{Name: f.name, Type: f.typ}
		msg[f.name] = f.value
	}
	return apitypes.TypedData{
		Types:       apitypes.Types{"EIP712Domain": eip712DomainType, primary: types},
		PrimaryType: primary,
		Domain: apitypes.TypedDataDomain{
			Name: name, Version: version,
			ChainId:           (*math.HexOrDecimal256)(chainID),
			VerifyingContract: common.HexToAddress(verifying).Hex(),
		},
		Message: msg,
	}
}

func commitmentTypedData(primary string, d commitmentDomain, fields []tdField) apitypes.TypedData {
	return typedData(primary, d.Name, d.Version, big.NewInt(d.ChainID), d.VerifyingContract, fields)
}

// decField parses a decimal integer field into its canonical decimal string.
func decField(name, s string) (string, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return "", fmt.Errorf("invalid %s: %q", name, s)
	}
	return n.String(), nil
}

// b32Field parses a bytes32 field into 0x-hex.
func b32Field(name, s string) (string, error) {
	b, err := hexToBytes32(s)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", name, err)
	}
	return "0x" + hex.EncodeToString(b[:]), nil
}

// fieldsOf resolves a field list in order, stopping at the first parse error.
func fieldsOf(specs ...func() (tdField, error)) ([]tdField, error) {
	out := make([]tdField, 0, len(specs))
	for _, f := range specs {
		v, err := f()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func dec(name, s string) func() (tdField, error) {
	return func() (tdField, error) { v, err := decField(name, s); return tdField{name, "uint256", v}, err }
}

func decN(name, typ, s string) func() (tdField, error) {
	return func() (tdField, error) { v, err := decField(name, s); return tdField{name, typ, v}, err }
}

func b32(name, s string) func() (tdField, error) {
	return func() (tdField, error) { v, err := b32Field(name, s); return tdField{name, "bytes32", v}, err }
}

func str(name, s string) func() (tdField, error) {
	return func() (tdField, error) { return tdField{name, "string", s}, nil }
}

func reviewTypedData(p reviewCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), dec("merchantId", m.MerchantID), b32("productId", m.ProductID),
		b32("contentHash", m.ContentHash), dec("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("ReviewCommitment", p.Domain, f), err
}

func voteTypedData(p voteCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), dec("escrowId", m.EscrowID), b32("votesHash", m.VotesHash),
		dec("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("VoteCommitment", p.Domain, f), err
}

func cashbackRateTypedData(p cashbackRateCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), decN("cashbackOfCommissionBps", "uint16", m.CashbackOfCommissionBps),
		b32("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("CashbackRateCommitment", p.Domain, f), err
}

func intentAccessTypedData(p intentAccessCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), b32("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("IntentAccessCommitment", p.Domain, f), err
}

func intentMarkTypedData(p intentMarkCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), str("intentId", m.IntentID), str("result", m.Result),
		b32("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("IntentMarkCommitment", p.Domain, f), err
}

func intentSkipTypedData(p intentSkipCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), str("intentId", m.IntentID), str("reason", m.Reason),
		b32("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("IntentSkipCommitment", p.Domain, f), err
}

func telegramLinkTypedData(p telegramLinkCommitmentPayload) (apitypes.TypedData, error) {
	m := p.Message
	f, err := fieldsOf(dec("agentId", m.AgentID), b32("nonce", m.Nonce), dec("expiry", m.Expiry))
	return commitmentTypedData("TelegramLinkCommitment", p.Domain, f), err
}

func chargeTypedData(payer common.Address, paymentRef [32]byte, buyerAgentID *big.Int, attributionTokenHash [32]byte, chainID int64, verifyingContract common.Address) (apitypes.TypedData, error) {
	return typedData("ChargeCommitment", chargeDomainName, "1", big.NewInt(chainID), verifyingContract.Hex(), []tdField{
		{"payer", "address", payer.Hex()},
		{"paymentRef", "bytes32", "0x" + hex.EncodeToString(paymentRef[:])},
		{"buyerAgentId", "uint256", buyerAgentID.String()},
		{"attributionTokenHash", "bytes32", "0x" + hex.EncodeToString(attributionTokenHash[:])},
	}), nil
}

func erc3009ReceiveTypedData(auth evm.ExactEIP3009Authorization, chainID *big.Int, tokenAddr, tokenName, tokenVersion string) (apitypes.TypedData, error) {
	f, err := fieldsOf(
		func() (tdField, error) { return tdField{"from", "address", common.HexToAddress(auth.From).Hex()}, nil },
		func() (tdField, error) { return tdField{"to", "address", common.HexToAddress(auth.To).Hex()}, nil },
		dec("value", auth.Value), dec("validAfter", auth.ValidAfter), dec("validBefore", auth.ValidBefore),
		b32("nonce", auth.Nonce))
	return typedData(erc3009ReceiveAuthorizationType, tokenName, tokenVersion, chainID, tokenAddr, f), err
}

// signTyped signs td only if its EIP-712 hash equals want, the digest the hand-rolled encoder
// computed for the same commitment.
func signTyped(ctx context.Context, s Signer, td apitypes.TypedData, want []byte) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	if !bytes.Equal(hash, want) {
		return nil, fmt.Errorf("typed data hash %x does not match the commitment digest %x", hash, want)
	}
	return s.SignTypedData(ctx, td)
}
