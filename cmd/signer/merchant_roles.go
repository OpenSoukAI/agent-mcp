package main

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── grant_merchant_role / revoke_merchant_role ──────────────────────────────────
//
// Per-merchant roles let an owner delegate one capability to a key without handing over the
// identity. Until REF-324 nothing in this repo could set one, so an agent-run merchant had to
// build a raw contract call to give its server a settlement key.
//
// The roles are scoped to one merchant: granting PRODUCT_MANAGER_ROLE for merchant 7 says
// nothing about merchant 8, and holding one role never implies another.

// merchantRoles maps the names MerchantAccessControl._roleExists allowlists to their ids.
//
// Hand-mirrored, like the ProductType ordinals: the ABI carries only the hash, so a misspelled
// name here compiles and reverts InvalidRole on-chain after the agent has paid for the
// transaction. merchant_roles_test.go pins each hash to the literal the contracts suite
// asserts, which is what makes a rename on either side fail loudly.
var merchantRoles = map[string]common.Hash{
	"SETTLEMENT_SIGNER_ROLE":  crypto.Keccak256Hash([]byte("SETTLEMENT_SIGNER_ROLE")),
	"PRODUCT_MANAGER_ROLE":    crypto.Keccak256Hash([]byte("PRODUCT_MANAGER_ROLE")),
	"COMMISSION_MANAGER_ROLE": crypto.Keccak256Hash([]byte("COMMISSION_MANAGER_ROLE")),
}

// roleNames lists the accepted names in a stable order, for error messages.
func roleNames() []string {
	names := make([]string, 0, len(merchantRoles))
	for name := range merchantRoles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// parseMerchantRole resolves a role NAME rather than accepting a raw hash. A hash the
// contract does not allowlist reverts InvalidRole, and a hash that is merely wrong — say the
// keccak of a name without its _ROLE suffix — would be granted successfully and then never
// checked by anything, which is worse: a delegation that silently does nothing.
func parseMerchantRole(name string) (common.Hash, error) {
	role, ok := merchantRoles[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return common.Hash{}, fmt.Errorf(
			"invalid role: %q — the per-merchant roles are %s",
			name, strings.Join(roleNames(), ", "))
	}
	return role, nil
}

func hexRole(role common.Hash) string { return role.Hex() }

// parseRoleAccount validates the address strictly instead of using common.HexToAddress, which
// left-pads a short string and truncates a long one. Both turn a typo into a different, valid
// address — and granting a role to it is a transaction that succeeds, costs gas, and delegates
// nothing. The zero address is refused for the same reason: it is what a missing value becomes.
func parseRoleAccount(s string) (common.Address, error) {
	trimmed := strings.TrimSpace(s)
	if !common.IsHexAddress(trimmed) {
		return common.Address{}, fmt.Errorf(
			"invalid account: %q (want a 0x-prefixed 20-byte hex address)", s)
	}
	addr := common.HexToAddress(trimmed)
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf(
			"invalid account: the zero address cannot hold a role — pass the address of the key you want to delegate to")
	}
	return addr, nil
}

type merchantRoleInput struct {
	MerchantID string `json:"merchant_id"`        // decimal; the merchant's own ERC-8004 id
	Role       string `json:"role"`               // SETTLEMENT_SIGNER_ROLE | PRODUCT_MANAGER_ROLE | COMMISSION_MANAGER_ROLE
	Account    string `json:"account"`            // 0x address to grant to / revoke from
	ChainID    string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env
}

type merchantRoleOutput struct {
	MerchantID string `json:"merchant_id"`
	Role       string `json:"role"`
	RoleID     string `json:"role_id"`
	Account    string `json:"account"`
	// TxHash is empty when the account was already in the requested state and no
	// transaction was needed.
	TxHash    string `json:"tx_hash,omitempty"`
	HasRole   bool   `json:"has_role"`   // the state AFTER this call
	NoChange  bool   `json:"no_change"`  // already in that state; nothing was sent
	NextSteps string `json:"next_steps"` // empty on revoke
}

// Both writes go through onlyMerchantAdmin, which compares msg.sender to the ERC-8004 owner
// and nothing else — holding a role never confers the power to hand it out.
var merchantRoleRevertTable = newRevertTable(map[string]string{
	"NotMerchantOwner(uint256,address)": "the signer key does not own this merchant identity — only the ERC-8004 owner may grant or revoke a merchant's roles, and holding a role does not let a key pass it on",
	"MerchantNotFound(uint256)":         "no ERC-8004 identity exists for that merchant_id on this chain — check chain_id points at the chain the identity was minted on",
	"InvalidRole(bytes32)":              "the contract does not recognise that role id — this build of the tool and the deployed MerchantRegistry disagree about the role set",
	"UseMerchantScopedRole()":           "that call reached the two-argument AccessControl grantRole, which this registry refuses — roles here are per-merchant and take a merchant id",
})

func handleGrantMerchantRole(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in merchantRoleInput,
) (*sdkmcp.CallToolResult, merchantRoleOutput, error) {
	return applyMerchantRole(ctx, in, true)
}

func handleRevokeMerchantRole(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in merchantRoleInput,
) (*sdkmcp.CallToolResult, merchantRoleOutput, error) {
	return applyMerchantRole(ctx, in, false)
}

// applyMerchantRole is grant and revoke, which differ only in the method called and the state
// they are driving towards. Both read first: re-running after a failure then costs no gas, and
// an id that was never minted reverts on the read rather than on a paid-for transaction.
func applyMerchantRole(
	ctx context.Context,
	in merchantRoleInput,
	want bool,
) (*sdkmcp.CallToolResult, merchantRoleOutput, error) {
	tool, method := "revoke_merchant_role", "revokeRole"
	if want {
		tool, method = "grant_merchant_role", "grantRole"
	}

	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, merchantRoleOutput{}, err
	}
	role, err := parseMerchantRole(in.Role)
	if err != nil {
		return nil, merchantRoleOutput{}, err
	}
	account, err := parseRoleAccount(in.Account)
	if err != nil {
		return nil, merchantRoleOutput{}, err
	}

	out := merchantRoleOutput{
		MerchantID: merchantID.String(),
		Role:       strings.ToUpper(strings.TrimSpace(in.Role)),
		RoleID:     role.Hex(),
		Account:    account.Hex(),
		HasRole:    want,
	}

	held, err := readHasMerchantRole(ctx, tool, merchantID, role, account, in.ChainID)
	if err != nil {
		return nil, merchantRoleOutput{}, err
	}
	if held == want {
		out.NoChange = true
		out.NextSteps = roleNextSteps(want, out.Role, true)
		return nil, out, nil
	}

	w := merchantWrite{
		tool:    tool,
		addrEnv: "MERCHANT_REGISTRY_ADDRESS",
		abi:     merchantRegistryABI,
		method:  method,
		reverts: merchantRoleRevertTable,
		advice:  "check: does the signer key own this merchant's ERC-8004 identity?",
	}
	txHash, _, err := w.send(ctx, merchantID, in.ChainID, merchantID, role, account)
	if err != nil {
		return nil, merchantRoleOutput{}, err
	}
	out.TxHash = txHash
	out.NextSteps = roleNextSteps(want, out.Role, false)
	return nil, out, nil
}

// roleNextSteps says what the grant actually enables, because the role is inert until
// something off-chain is pointed at the key — and for a settlement signer the ORDER is the
// part that bites: deploying a key before its grant lands takes the merchant's sales down.
func roleNextSteps(granted bool, role string, noChange bool) string {
	if !granted {
		if role == "SETTLEMENT_SIGNER_ROLE" {
			return "stop that key signing settlements BEFORE revoking, or its /verify and /settle calls start failing immediately"
		}
		return ""
	}
	prefix := ""
	if noChange {
		prefix = "already held; "
	}
	switch role {
	case "SETTLEMENT_SIGNER_ROLE":
		return prefix + "that key may now sign the merchant's x402 /verify and /settle requests to the facilitator — deploy it to the merchant server AFTER this grant, never before, because an ungranted signature is refused on every sale"
	case "PRODUCT_MANAGER_ROLE":
		return prefix + "that key may now call add_product and set_product_active for this merchant, but NOT set_product_commission"
	case "COMMISSION_MANAGER_ROLE":
		return prefix + "that key may now call set_product_commission for this merchant, but NOT add or delist products"
	default:
		return prefix
	}
}

// readHasMerchantRole calls MerchantRegistry.hasRole, the per-merchant three-argument one.
func readHasMerchantRole(
	ctx context.Context,
	tool string,
	merchantID *big.Int,
	role common.Hash,
	account common.Address,
	chainIDOverride string,
) (bool, error) {
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
	if err := contract.Call(&bind.CallOpts{Context: ctx}, &out, "hasRole", merchantID, role, account); err != nil {
		if msg, ok := merchantRoleRevertTable.lookupErr(err); ok {
			return false, fmt.Errorf("%s cannot read the merchant's roles: %s", tool, msg)
		}
		return false, fmt.Errorf("read hasRole(%s, %s, %s): %w", merchantID, role.Hex(), account.Hex(), err)
	}
	if len(out) != 1 {
		return false, fmt.Errorf("hasRole returned %d values", len(out))
	}
	held, ok := out[0].(bool)
	if !ok {
		return false, fmt.Errorf("hasRole returned %T, want bool", out[0])
	}
	return held, nil
}
