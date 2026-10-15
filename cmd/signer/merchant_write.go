package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// ── Merchant-side contract writes ───────────────────────────────────────────────
//
// The merchant tools (REF-251) all send one transaction from the merchant's own key and
// differ only in contract, method, arguments and revert advice. merchantWrite is that
// difference; send is everything else.
//
// merchantId IS the ERC-8004 agentId, so the signing key is looked up by merchant id —
// AGENT_KEYS must carry an entry for it. A merchant operating without a browser is an
// agent like any other.
//
// bps is the protocol's commission denominator: 10_000 = 100%.
const bpsDenom = 10_000

type merchantWrite struct {
	tool    string // the MCP tool name, for error prefixes
	addrKey protocolKey
	abi     abi.ABI
	method  string
	reverts revertTable
	// advice is appended to a failure that carried no decodable revert data — a receipt-level
	// revert reaches us without one, and an agent staring at a bare tx hash cannot act.
	advice string
}

// send signs and sends the write, waits for it to be mined, and returns the tx hash and
// the sending address.
func (w merchantWrite) send(
	ctx context.Context,
	merchantID *big.Int,
	chainIDOverride string,
	args ...any,
) (txHash string, from string, err error) {
	privKey, err := signerKeys.KeyFor(merchantID.String())
	if err != nil {
		return "", "", err
	}

	client, chainIDInt, err := dialChain(ctx, chainIDOverride)
	if err != nil {
		return "", "", err
	}
	defer client.Close()
	contractAddr, err := resolveAddress(ctx, chainIDInt, w.addrKey)
	if err != nil {
		return "", "", err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return "", "", fmt.Errorf("build transactor: %w", err)
	}

	contract := bind.NewBoundContract(contractAddr, w.abi, client, client, client)

	tx, err := contract.Transact(auth, w.method, args...)
	if err != nil {
		if msg, ok := w.reverts.lookupErr(err); ok {
			return "", "", fmt.Errorf("%s would revert: %s", w.tool, msg)
		}
		return "", "", fmt.Errorf("%s tx: %w (%s)", w.tool, err, w.advice)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return "", "", fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return "", "", fmt.Errorf("%s tx reverted: %s (%s)", w.tool, tx.Hash().Hex(), w.advice)
	}

	return tx.Hash().Hex(), crypto.PubkeyToAddress(privKey.PublicKey).Hex(), nil
}

// parseMerchantID accepts the decimal ERC-8004 agentId that identifies the merchant.
//
// Zero IS a valid identity: IdentityRegistry.register() returns 0 for the first mint, and
// ownerOf(0) resolves. Rejecting it here would lock the first merchant on a registry out of
// every tool below, and would disagree with POST /v1/merchant/product, which bounds at < 0.
func parseMerchantID(s string) (*big.Int, error) {
	id, ok := new(big.Int).SetString(strings.TrimSpace(s), 10)
	if !ok {
		return nil, fmt.Errorf("invalid merchant_id: %q (want a decimal string)", s)
	}
	if id.Sign() < 0 {
		return nil, fmt.Errorf("invalid merchant_id: %s (must not be negative)", id)
	}
	return id, nil
}

// parseProductID accepts the on-chain productId: 0x-prefixed 32-byte hex, matching what
// POST /v1/merchant/product takes. It is deliberately strict about the length rather than
// padding a short value, because common.HexToHash-style left-padding would turn a typo
// into a different, valid, empty product slot.
func parseProductID(s string) ([32]byte, error) {
	var out [32]byte

	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "0x") && !strings.HasPrefix(trimmed, "0X") {
		return out, fmt.Errorf("invalid product_id: %q (want 0x-prefixed 32-byte hex)", s)
	}
	raw, err := hex.DecodeString(trimmed[2:])
	if err != nil {
		return out, fmt.Errorf("invalid product_id: %q is not hex", s)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("invalid product_id: %d bytes (want exactly 32)", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// parseCommissionBps bounds the rate the contract would bound anyway (InvalidRates above
// 10_000), so the agent gets the limit named instead of a selector.
func parseCommissionBps(bps int) (uint16, error) {
	if bps < 0 || bps > bpsDenom {
		return 0, fmt.Errorf("invalid commission_bps: %d (want 0–%d, where %d = 100%%)",
			bps, bpsDenom, bpsDenom)
	}
	return uint16(bps), nil
}
