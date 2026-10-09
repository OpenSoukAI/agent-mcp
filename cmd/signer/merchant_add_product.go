package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── add_product ─────────────────────────────────────────────────────────────────
//
// ProductRegistry.addProduct followed by POST /v1/merchant/product. The chain holds the
// commission rate and the active flag; the backend holds the name, description, category
// and endpoint URL that make the product discoverable. A product with only the first half
// is payable but invisible.
//
// addProduct reverts ProductAlreadyExists, so a naive retry after a failed sync is
// impossible — the exact hazard REF-254 was about. Instead the tool reads the product
// first and skips the chain write when it is already there, which makes re-running the
// tool the retry path for a half-finished add.

type addProductInput struct {
	MerchantID    string `json:"merchant_id"`    // decimal; the merchant's own ERC-8004 id
	ProductID     string `json:"product_id"`     // 0x-prefixed 32-byte hex, unique per merchant
	CommissionBps int    `json:"commission_bps"` // 0–10000; 1000 = 10%
	EndpointURL   string `json:"endpoint_url"`   // the product's x402 payment endpoint
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Category      string `json:"category,omitempty"` // a doc-22 slug from GET /v1/product-categories
	// PublicEndpointURL is the merchant's own public x402 endpoint for the same product, if it has
	// one (REF-398). Merchant-only: the backend never shows it to buyers.
	PublicEndpointURL string `json:"public_endpoint_url,omitempty"`
	// ProductCardURI points at off-chain product metadata JSON. On-chain and optional.
	ProductCardURI string `json:"product_card_uri,omitempty"`
	ChainID        string `json:"chain_id,omitempty"`
}

type addProductOutput struct {
	MerchantID string `json:"merchant_id"`
	ProductID  string `json:"product_id"`
	// TxHash is empty when the product was already on-chain and no transaction was needed.
	TxHash         string `json:"tx_hash,omitempty"`
	AlreadyOnChain bool   `json:"already_on_chain"`
	CommissionBps  int    `json:"commission_bps"` // what is on-chain now
	MetadataSynced bool   `json:"metadata_synced"`
	// CommissionWarning is set when the product already existed on-chain at a DIFFERENT rate
	// than the call asked for. The rate is not changed here.
	CommissionWarning string `json:"commission_warning,omitempty"`
	NextSteps         string `json:"next_steps"`
}

var addProductRevertTable = newRevertTable(map[string]string{
	"Unauthorised(uint256,bytes32,address)": "the signer key is neither the merchant identity's owner nor a PRODUCT_MANAGER for this merchant",
	"MerchantNotActive(uint256)":            "the merchant is not active on-chain — call activate_merchant first; products cannot be added to an inactive merchant",
	"ProductAlreadyExists(uint256,bytes32)": "a product with that product_id already exists for this merchant (product ids are unique per merchant, and this tool normally skips the chain write when it finds one — seeing this means the product appeared between the check and the send)",
	"InvalidRates(uint16)":                  "commission_bps exceeds 10000 (100%)",
})

func handleAddProduct(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in addProductInput,
) (*sdkmcp.CallToolResult, addProductOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, addProductOutput{}, err
	}
	restID, err := merchantIDForREST(merchantID)
	if err != nil {
		return nil, addProductOutput{}, err
	}
	productID, err := parseProductID(in.ProductID)
	if err != nil {
		return nil, addProductOutput{}, err
	}
	bps, err := parseCommissionBps(in.CommissionBps)
	if err != nil {
		return nil, addProductOutput{}, err
	}
	if strings.TrimSpace(in.EndpointURL) == "" {
		return nil, addProductOutput{}, fmt.Errorf("endpoint_url is required (the product's x402 payment endpoint)")
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, addProductOutput{}, fmt.Errorf("name is required (buyers and discovery see it)")
	}
	// Checked here because the backend's own check comes after addProduct, when the gas is spent.
	if err := checkEndpointPair(in.EndpointURL, in.PublicEndpointURL); err != nil {
		return nil, addProductOutput{}, err
	}
	if err := checkCategory(ctx, in.Category); err != nil {
		return nil, addProductOutput{}, err
	}

	out := addProductOutput{
		MerchantID:    merchantID.String(),
		ProductID:     in.ProductID,
		CommissionBps: int(bps),
	}

	// Read first, for the same reason as activate_merchant: addProduct cannot be repeated, so
	// without this a sync failure would strand the product on-chain with no way to finish.
	existing, found, err := readProductCommission(ctx, merchantID, productID, in.ChainID)
	if err != nil {
		return nil, addProductOutput{}, err
	}

	if found {
		out.AlreadyOnChain = true
		out.CommissionBps = int(existing)
		if existing != bps {
			// Deliberately not changed here. Repricing is a financial change gated on a
			// different role, and doing it as a side effect of an "add" the caller believed
			// was a create would move money quietly.
			out.CommissionWarning = fmt.Sprintf(
				"this product is already on-chain at %d bps, not the %d bps requested; the rate was "+
					"NOT changed — call set_product_commission if you meant to reprice it", existing, bps)
		}
	} else {
		w := merchantWrite{
			tool:    "add_product",
			addrEnv: "PRODUCT_REGISTRY_ADDRESS",
			abi:     productRegistryABI,
			method:  "addProduct",
			reverts: addProductRevertTable,
			advice:  "check: is the merchant active on-chain (activate_merchant), does the signer key own it or hold PRODUCT_MANAGER, and is commission_bps within 0–10000?",
		}
		txHash, _, err := w.send(ctx, merchantID, in.ChainID, merchantID, productID, bps,
			productTypeRepeat, in.ProductCardURI)
		if err != nil {
			return nil, addProductOutput{}, err
		}
		out.TxHash = txHash
	}

	body, err := json.Marshal(productMetadataBody(restID, in))
	if err != nil {
		return nil, addProductOutput{}, fmt.Errorf("encode product metadata: %w", err)
	}

	if _, err := callAuthedRaw(ctx, "add_product", http.MethodPost, "/v1/merchant/product",
		body, merchantID, map[int]string{
			http.StatusConflict:   "this merchant has no backend record — call activate_merchant first, then add_product again",
			http.StatusNotFound:   "the backend cannot see this product on-chain yet; its indexer may be a block behind — call add_product again in a few seconds",
			http.StatusBadRequest: "the backend rejected a field; the message above names which one",
		}); err != nil {
		return nil, addProductOutput{}, productSyncFailed(out, err)
	}
	out.MetadataSynced = true

	out.NextSteps = "check_product_readiness on the endpoint_url to confirm it is wired for referral payments"
	return nil, out, nil
}

// productMetadataBody is the backend half. Optional fields go only when given: since REF-398
// the write is partial and "" clears a stored value, so sending empties would make a retry
// with fewer fields wipe what an earlier call stored.
func productMetadataBody(restID int64, in addProductInput) map[string]any {
	body := map[string]any{
		"merchant_id":  restID,
		"product_id":   in.ProductID,
		"endpoint_url": in.EndpointURL,
		"name":         in.Name,
	}
	if in.Description != "" {
		body["description"] = in.Description
	}
	if in.Category != "" {
		body["category"] = in.Category
	}
	if in.PublicEndpointURL != "" {
		body["public_endpoint_url"] = in.PublicEndpointURL
	}
	return body
}

// productSyncFailed reports the split state: the product exists on-chain and the backend
// does not know about it, so it can take payments but cannot be discovered. The agent needs
// to be told that re-running is both safe and necessary — addProduct on its own would
// revert ProductAlreadyExists, which reads like a dead end.
func productSyncFailed(out addProductOutput, err error) error {
	chainState := "the product was already on-chain, so no transaction was sent"
	if out.TxHash != "" {
		chainState = fmt.Sprintf("the on-chain addProduct SUCCEEDED (tx %s) and the gas is spent", out.TxHash)
	}
	return fmt.Errorf("%w\n\nSTATE: %s, but the product's metadata did not reach the backend, so "+
		"it is payable and NOT discoverable. Call add_product again with the same product_id: the "+
		"chain write is skipped when the product already exists, so the retry only repeats the sync",
		err, chainState)
}

// readProductCommission returns the product's on-chain commission, and whether it exists.
// getProduct REVERTS ProductNotFound rather than returning a zero struct, so absence
// arrives as an error and has to be told apart from a real failure by its selector.
func readProductCommission(
	ctx context.Context,
	merchantID *big.Int,
	productID [32]byte,
	chainIDOverride string,
) (uint16, bool, error) {
	addr, err := requireAddr("PRODUCT_REGISTRY_ADDRESS")
	if err != nil {
		return 0, false, err
	}

	client, _, err := dialChain(ctx, chainIDOverride)
	if err != nil {
		return 0, false, err
	}
	defer client.Close()

	var out []any
	contract := bind.NewBoundContract(addr, productRegistryABI, client, client, client)
	if err := contract.Call(&bind.CallOpts{Context: ctx}, &out, "getProduct", merchantID, productID); err != nil {
		if _, isNotFound := productNotFoundTable.lookupErr(err); isNotFound {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read getProduct: %w", err)
	}

	p, ok := out[0].(struct {
		MerchantId     *big.Int `json:"merchantId"`
		ProductId      [32]byte `json:"productId"`
		CommissionBps  uint16   `json:"commissionBps"`
		Active         bool     `json:"active"`
		ProductCardURI string   `json:"productCardURI"`
		CreatedAt      *big.Int `json:"createdAt"`
		ProductType    uint8    `json:"productType"`
	})
	if !ok {
		return 0, false, fmt.Errorf("getProduct returned %T", out[0])
	}
	return p.CommissionBps, true, nil
}

// productNotFoundTable exists to CLASSIFY one selector rather than to explain it: an
// absent product is a normal branch here, not a failure to report.
var productNotFoundTable = newRevertTable(map[string]string{
	"ProductNotFound(uint256,bytes32)": "absent",
})
