package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── activate_merchant ───────────────────────────────────────────────────────────
//
// Three operations, not two. MerchantRegistry.setActive flips the on-chain flag;
// POST /v1/agent/register creates the agents row; POST /v1/merchant/register creates the
// merchants row, which has a foreign key onto that agents row. Skipping the agent step
// leaves the merchant registration failing on a constraint that names neither.
//
// The order is forced from both ends: /merchant/register refuses a merchant that is not
// active on-chain (403), and /merchant/product later refuses a merchant with no backend
// row (409). So chain first, then agent, then merchant.
//
// Every step is idempotent, which is what makes re-running this tool the retry path for a
// half-finished activation: setActive is skipped when the flag is already set, and both
// registrations treat "already registered" as done. A composite that could not be re-run
// would leave an agent holding a paid-for on-chain write and no way to finish the sync.

type activateMerchantInput struct {
	MerchantID string `json:"merchant_id"`        // decimal; the merchant's own ERC-8004 id
	ChainID    string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env
}

type activateMerchantOutput struct {
	MerchantID string `json:"merchant_id"`
	// TxHash is empty when the merchant was already active on-chain and no transaction
	// was needed.
	TxHash             string `json:"tx_hash,omitempty"`
	AlreadyActive      bool   `json:"already_active"`
	AgentRegistered    string `json:"agent_registered"`    // "created" | "already_registered"
	MerchantRegistered string `json:"merchant_registered"` // "created" | "already_registered"
	NextSteps          string `json:"next_steps"`
}

var setMerchantActiveRevertTable = newRevertTable(map[string]string{
	"NotMerchantOwner(uint256,address)": "the signer key does not own this merchant identity — setActive is callable only by the ERC-8004 owner, and minting the identity is out of scope for these tools",
	"MerchantIsSuspended(uint256)":      "this merchant has been suspended by the protocol and cannot reactivate itself — only a protocol admin can lift a suspension",
	"MerchantNotFound(uint256)":         "no ERC-8004 identity exists for that merchant_id on this chain — mint the identity first",
})

func handleActivateMerchant(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in activateMerchantInput,
) (*sdkmcp.CallToolResult, activateMerchantOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, activateMerchantOutput{}, err
	}
	restID, err := merchantIDForREST(merchantID)
	if err != nil {
		return nil, activateMerchantOutput{}, err
	}

	out := activateMerchantOutput{MerchantID: merchantID.String()}

	// Read before writing. A re-run after a failed sync then costs no gas, and the read also
	// reverts MerchantNotFound for an unminted id — which is a clearer failure than a
	// transaction that reverts after the agent has paid for it.
	active, err := readMerchantActive(ctx, merchantID, in.ChainID)
	if err != nil {
		return nil, activateMerchantOutput{}, err
	}

	if active {
		out.AlreadyActive = true
	} else {
		w := merchantWrite{
			tool:    "activate_merchant",
			addrEnv: "MERCHANT_REGISTRY_ADDRESS",
			abi:     merchantRegistryABI,
			method:  "setActive",
			reverts: setMerchantActiveRevertTable,
			advice:  "check: does the signer key own this merchant's ERC-8004 identity, and is the merchant suspended?",
		}
		txHash, _, err := w.send(ctx, merchantID, in.ChainID, merchantID, true)
		if err != nil {
			return nil, activateMerchantOutput{}, err
		}
		out.TxHash = txHash
	}

	// From here the on-chain flag is set. Any failure below is a sync failure, and the error
	// says so — the gas is already spent and a blind retry of the whole tool is safe.
	agentStatus, err := registerIdentity(ctx, "activate_merchant", "/v1/agent/register",
		map[string]any{"agent_id": restID}, merchantID, "agent")
	if err != nil {
		return nil, activateMerchantOutput{}, syncFailedAfterChain(out.TxHash, err)
	}
	out.AgentRegistered = agentStatus

	merchantStatus, err := registerIdentity(ctx, "activate_merchant", "/v1/merchant/register",
		map[string]any{"merchant_id": restID}, merchantID, "merchant")
	if err != nil {
		return nil, activateMerchantOutput{}, syncFailedAfterChain(out.TxHash, err)
	}
	out.MerchantRegistered = merchantStatus

	out.NextSteps = "set_merchant_profile to publish a description, then add_product for each product"
	return nil, out, nil
}

// registerIdentity posts one of the two registration endpoints and folds "already
// registered" into success. Both answer 201 on creation and 409 when the row exists, and a
// 409 here means the work is done — treating it as an error would make the second run of a
// resumed activation fail on the step that had actually succeeded.
func registerIdentity(
	ctx context.Context,
	tool, path string,
	payload map[string]any,
	merchantID *big.Int,
	what string,
) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode %s registration: %w", what, err)
	}

	_, err = callAuthedRaw(ctx, tool, http.MethodPost, path, body, merchantID, map[int]string{
		http.StatusForbidden: forbiddenAdvice(what),
		http.StatusNotFound:  "the identity does not exist on-chain for this chain — check chain_id points at the chain the identity was minted on",
	})
	if err != nil {
		if restStatus(err) == http.StatusConflict {
			return "already_registered", nil
		}
		return "", err
	}
	return "created", nil
}

func forbiddenAdvice(what string) string {
	if what == "merchant" {
		// /merchant/register 403s for TWO unrelated reasons, and only one is about ownership.
		return "either the signing key does not own this merchant, or the merchant is not active on-chain — the message above says which"
	}
	return "the signing key does not own this identity"
}

// syncFailedAfterChain marks the failure mode this whole design exists for: the chain write
// landed and the backend did not catch up. The agent must know the gas is spent and that
// repeating the call is safe, or it will either give up or go looking for a way to undo a
// transaction that cannot be undone.
func syncFailedAfterChain(txHash string, err error) error {
	spent := "the merchant was already active on-chain, so no transaction was sent"
	if txHash != "" {
		spent = fmt.Sprintf("the on-chain activation SUCCEEDED (tx %s) and the gas is spent", txHash)
	}
	return fmt.Errorf("%w\n\nSTATE: %s, but the backend sync did not complete. "+
		"Call activate_merchant again with the same merchant_id: the on-chain step is skipped "+
		"when the flag is already set, so the retry only repeats the sync", err, spent)
}

// readMerchantActive calls MerchantRegistry.isActive.
func readMerchantActive(ctx context.Context, merchantID *big.Int, chainIDOverride string) (bool, error) {
	addr, err := requireAddr("MERCHANT_REGISTRY_ADDRESS")
	if err != nil {
		return false, err
	}

	client, _, err := dialChain(ctx, chainIDOverride)
	if err != nil {
		return false, err
	}
	defer client.Close()

	var out []any
	contract := bind.NewBoundContract(addr, merchantRegistryABI, client, client, client)
	if err := contract.Call(&bind.CallOpts{Context: ctx}, &out, "isActive", merchantID); err != nil {
		if msg, ok := setMerchantActiveRevertTable.lookupErr(err); ok {
			return false, fmt.Errorf("activate_merchant cannot read the merchant: %s", msg)
		}
		return false, fmt.Errorf("read isActive(%s): %w", merchantID, err)
	}
	if len(out) != 1 {
		return false, fmt.Errorf("isActive returned %d values", len(out))
	}
	active, ok := out[0].(bool)
	if !ok {
		return false, fmt.Errorf("isActive returned %T, want bool", out[0])
	}
	return active, nil
}
