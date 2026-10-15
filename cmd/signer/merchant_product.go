package main

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── set_product_commission ──────────────────────────────────────────────────────

type setProductCommissionInput struct {
	MerchantID    string `json:"merchant_id"`        // decimal; the merchant's own ERC-8004 id
	ProductID     string `json:"product_id"`         // 0x-prefixed 32-byte hex
	CommissionBps int    `json:"commission_bps"`     // 0–10000; 1000 = 10%
	ChainID       string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env
}

type setProductCommissionOutput struct {
	TxHash        string `json:"tx_hash"`
	MerchantID    string `json:"merchant_id"`
	ProductID     string `json:"product_id"`
	CommissionBps int    `json:"commission_bps"`
	SetBy         string `json:"set_by"` // = signer address
}

// Unauthorised here means the COMMISSION_MANAGER role specifically. setProductActive's
// table names PRODUCT_MANAGER for the same selector, which is why the two tables are
// separate: the role a caller is missing is the whole content of the advice.
var setCommissionRevertTable = newRevertTable(map[string]string{
	"Unauthorised(uint256,bytes32,address)": "the signer key is neither the merchant identity's owner nor a COMMISSION_MANAGER for this merchant — commission changes are gated separately from product changes, so a PRODUCT_MANAGER key cannot make them",
	"ProductNotFound(uint256,bytes32)":      "no product with that product_id exists for this merchant — add_product first, and check the id is the on-chain bytes32 rather than a slug",
	"InvalidRates(uint16)":                  "commission_bps exceeds 10000 (100%)",
})

func handleSetProductCommission(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in setProductCommissionInput,
) (*sdkmcp.CallToolResult, setProductCommissionOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, setProductCommissionOutput{}, err
	}
	productID, err := parseProductID(in.ProductID)
	if err != nil {
		return nil, setProductCommissionOutput{}, err
	}
	bps, err := parseCommissionBps(in.CommissionBps)
	if err != nil {
		return nil, setProductCommissionOutput{}, err
	}

	w := merchantWrite{
		tool:    "set_product_commission",
		addrKey: keyProductRegistry,
		abi:     productRegistryABI,
		method:  "setCommission",
		reverts: setCommissionRevertTable,
		advice:  "check: does the signer key own merchant_id or hold COMMISSION_MANAGER for it, and does the product exist?",
	}

	txHash, from, err := w.send(ctx, merchantID, in.ChainID, merchantID, productID, bps)
	if err != nil {
		return nil, setProductCommissionOutput{}, err
	}

	return nil, setProductCommissionOutput{
		TxHash:        txHash,
		MerchantID:    merchantID.String(),
		ProductID:     in.ProductID,
		CommissionBps: int(bps),
		SetBy:         from,
	}, nil
}

// ── set_product_active ──────────────────────────────────────────────────────────

type setProductActiveInput struct {
	MerchantID string `json:"merchant_id"`
	ProductID  string `json:"product_id"`
	// Active is a pointer so an omitted field is an error rather than false. A plain bool
	// would make "set_product_active for product X" — with the flag forgotten — quietly
	// delist the product, which is the opposite of what the phrasing suggests.
	Active  *bool  `json:"active"`
	ChainID string `json:"chain_id,omitempty"`
}

type setProductActiveOutput struct {
	TxHash     string `json:"tx_hash"`
	MerchantID string `json:"merchant_id"`
	ProductID  string `json:"product_id"`
	Active     bool   `json:"active"`
	SetBy      string `json:"set_by"`
}

var setProductActiveRevertTable = newRevertTable(map[string]string{
	"Unauthorised(uint256,bytes32,address)": "the signer key is neither the merchant identity's owner nor a PRODUCT_MANAGER for this merchant",
	"ProductNotFound(uint256,bytes32)":      "no product with that product_id exists for this merchant — add_product first, and check the id is the on-chain bytes32 rather than a slug",
})

func handleSetProductActive(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in setProductActiveInput,
) (*sdkmcp.CallToolResult, setProductActiveOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, setProductActiveOutput{}, err
	}
	productID, err := parseProductID(in.ProductID)
	if err != nil {
		return nil, setProductActiveOutput{}, err
	}
	if in.Active == nil {
		return nil, setProductActiveOutput{}, fmt.Errorf("active is required (true to list the product, false to delist it)")
	}

	w := merchantWrite{
		tool:    "set_product_active",
		addrKey: keyProductRegistry,
		abi:     productRegistryABI,
		method:  "setProductActive",
		reverts: setProductActiveRevertTable,
		advice:  "check: does the signer key own merchant_id or hold PRODUCT_MANAGER for it, and does the product exist?",
	}

	txHash, from, err := w.send(ctx, merchantID, in.ChainID, merchantID, productID, *in.Active)
	if err != nil {
		return nil, setProductActiveOutput{}, err
	}

	return nil, setProductActiveOutput{
		TxHash:     txHash,
		MerchantID: merchantID.String(),
		ProductID:  in.ProductID,
		Active:     *in.Active,
		SetBy:      from,
	}, nil
}
