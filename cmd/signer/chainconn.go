package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ── Chain connection setup ──────────────────────────────────────────────────────
//
// Every transaction-sending tool opens with the same twenty lines: read BASE_RPC_URL,
// read the contract address it needs, resolve a chain id, dial. Only the resolution rule
// is subtle enough to be worth stating once — an explicit per-call override beats the
// CHAIN_ID env var, which beats the Base Sepolia default — and having it written out four
// times is four chances for one copy to drift.
//
// Address reads stay a SEPARATE call rather than a parameter of dialChain. That is what
// lets publish_escrow_review, which needs two addresses, use the same helpers as the
// tools that need one, without dialChain growing a variadic address list.
//
// pay_for_product is deliberately NOT a caller: it needs no contract address, wants the
// chain id as a *big.Int for x402 EIP-712 domains, and cross-checks the id against the
// ref link's own chain segment. Bending these helpers to fit it would cost more clarity
// than the duplication does.

// defaultChainID is the chain assumed when neither an explicit override nor CHAIN_ID is
// set. Every deployment to date is Base Sepolia; no Base mainnet deployment exists.
const defaultChainID = "84532"

// dialChain resolves the RPC endpoint and chain id, then dials. chainIDOverride is a
// tool's optional chain_id input — empty means "not supplied", falling through to
// CHAIN_ID and then to defaultChainID. The caller owns the returned client and must
// Close it.
func dialChain(ctx context.Context, chainIDOverride string) (*ethclient.Client, int64, error) {
	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, 0, fmt.Errorf("BASE_RPC_URL env var not set")
	}

	chainIDStr := chainIDOverride
	if chainIDStr == "" {
		chainIDStr = os.Getenv("CHAIN_ID")
	}
	if chainIDStr == "" {
		chainIDStr = defaultChainID
	}
	chainID, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid chain id %q: %w", chainIDStr, err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, 0, fmt.Errorf("dial rpc: %w", err)
	}
	return client, chainID, nil
}

// requireAddr reads a contract address from a required env var. It does not validate the
// address beyond non-emptiness: common.HexToAddress silently yields the zero address for
// malformed input, and a call to the zero address fails loudly at the RPC with the
// address in the error, which is a clearer signal than a parse complaint here would be.
func requireAddr(envVar string) (common.Address, error) {
	hexAddr := os.Getenv(envVar)
	if hexAddr == "" {
		return common.Address{}, fmt.Errorf("%s env var not set", envVar)
	}
	return common.HexToAddress(hexAddr), nil
}
