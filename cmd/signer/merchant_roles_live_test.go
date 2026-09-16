package main

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ── Live role-write tests (REF-324) ─────────────────────────────────────────────
//
// Same gating as merchant_live_test.go: skipped unless MERCHANT_LIVE_RPC is set.
//
// Only a node proves these three ABI entries describe the deployed MerchantRegistry.
// grantRole is overloaded there — the inherited two-argument AccessControl form exists
// alongside the per-merchant one and reverts UseMerchantScopedRole — so a literal that
// dropped merchantId would pack, send, and fail on-chain with the agent's gas spent.

// TestLive_GrantAndRevokeMerchantRole walks the whole round trip on one role, because the
// interesting failures are only visible across steps: a grant that lands on the wrong
// (merchant, role, account) triple still mines successfully, and only the read afterwards
// says whether it reached the slot the facilitator will check.
func TestLive_GrantAndRevokeMerchantRole(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.ownerKeyHex)

	otherKey, err := crypto.HexToECDSA(strings.TrimPrefix(e.otherKeyHex, "0x"))
	if err != nil {
		t.Fatalf("parse other key: %v", err)
	}
	grantee := crypto.PubkeyToAddress(otherKey.PublicKey).Hex()

	in := merchantRoleInput{
		MerchantID: e.merchantID,
		Role:       "SETTLEMENT_SIGNER_ROLE",
		Account:    grantee,
		ChainID:    e.chainID,
	}

	// Start from a known state; the account may hold the role from an earlier run.
	if _, out, err := handleRevokeMerchantRole(t.Context(), nil, in); err != nil {
		t.Fatalf("precondition revoke: %v", err)
	} else if out.HasRole {
		t.Fatal("revoke reported the role still held")
	}

	_, granted, err := handleGrantMerchantRole(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("grant_merchant_role: %v", err)
	}
	if granted.NoChange || granted.TxHash == "" {
		t.Fatalf("grant sent no transaction from a revoked state: %+v", granted)
	}
	if granted.RoleID != "0x9afba5c05b1dfbaa7188068a6610fc1a9f4c5b291aea74d5d9d8bc81f8d004f1" {
		t.Errorf("role_id = %s", granted.RoleID)
	}

	// The read the facilitator's own check mirrors. A grant written against a different
	// merchant, role or account mines just the same; this is what separates the two.
	held, err := readHasMerchantRole(t.Context(), "test", mustMerchantID(t, e.merchantID),
		merchantRoles["SETTLEMENT_SIGNER_ROLE"], mustRoleAccount(t, grantee), e.chainID)
	if err != nil {
		t.Fatalf("hasRole after grant: %v", err)
	}
	if !held {
		t.Fatal("hasRole is false after a mined grant — the write landed on some other slot")
	}

	// Re-granting must cost nothing: this is the retry path for an agent whose first call
	// failed after the transaction mined.
	_, again, err := handleGrantMerchantRole(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if !again.NoChange || again.TxHash != "" {
		t.Errorf("re-granting an already-held role sent a transaction: %+v", again)
	}

	// The three roles are independent: granting one must not confer another.
	for _, other := range []string{"PRODUCT_MANAGER_ROLE", "COMMISSION_MANAGER_ROLE"} {
		leaked, err := readHasMerchantRole(t.Context(), "test", mustMerchantID(t, e.merchantID),
			merchantRoles[other], mustRoleAccount(t, grantee), e.chainID)
		if err != nil {
			t.Fatalf("hasRole(%s): %v", other, err)
		}
		if leaked {
			t.Errorf("granting SETTLEMENT_SIGNER_ROLE also granted %s", other)
		}
	}

	_, revoked, err := handleRevokeMerchantRole(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("revoke_merchant_role: %v", err)
	}
	if revoked.NoChange || revoked.TxHash == "" {
		t.Fatalf("revoke sent no transaction while the role was held: %+v", revoked)
	}
	if revoked.HasRole {
		t.Error("revoke reported has_role true")
	}

	stillHeld, err := readHasMerchantRole(t.Context(), "test", mustMerchantID(t, e.merchantID),
		merchantRoles["SETTLEMENT_SIGNER_ROLE"], mustRoleAccount(t, grantee), e.chainID)
	if err != nil {
		t.Fatalf("hasRole after revoke: %v", err)
	}
	if stillHeld {
		t.Fatal("the role survived a mined revoke")
	}
}

// TestLive_GrantMerchantRole_NonOwnerRefused pins the rule the tool's description states:
// onlyMerchantAdmin compares msg.sender to the ERC-8004 owner and consults no role, so a
// key holding every role still cannot hand one out.
func TestLive_GrantMerchantRole_NonOwnerRefused(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.otherKeyHex) // signs as a key that owns nothing

	_, _, err := handleGrantMerchantRole(t.Context(), nil, merchantRoleInput{
		MerchantID: e.merchantID,
		Role:       "PRODUCT_MANAGER_ROLE",
		Account:    "0x000000000000000000000000000000000000dEaD",
		ChainID:    e.chainID,
	})
	if err == nil {
		t.Fatal("a non-owner granted a role")
	}
	// The decoded advice, not a bare selector: an agent that cannot read the failure cannot
	// act on it.
	if !strings.Contains(err.Error(), "does not own this merchant identity") {
		t.Errorf("refusal does not explain the ownership rule: %v", err)
	}
}

func mustMerchantID(t *testing.T, s string) *big.Int {
	t.Helper()
	id, err := parseMerchantID(s)
	if err != nil {
		t.Fatalf("parseMerchantID(%q): %v", s, err)
	}
	return id
}

func mustRoleAccount(t *testing.T, s string) common.Address {
	t.Helper()
	a, err := parseRoleAccount(s)
	if err != nil {
		t.Fatalf("parseRoleAccount(%q): %v", s, err)
	}
	return a
}
