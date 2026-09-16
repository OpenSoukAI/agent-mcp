package main

import (
	"strings"
	"testing"
)

// REF-324. The three per-merchant roles, with the hashes `cast keccak "<NAME>"` produces.
//
// Pinned, not derived: MerchantAccessControl._roleExists allowlists exactly these three, and
// the ABI carries only the hash — a role name misspelled here compiles, passes any test that
// hashes the same constant, and reverts InvalidRole on-chain after the agent has paid for the
// transaction. The contracts suite pins the same literals, so a rename breaks both repos.
var roleVectors = []struct {
	name string
	hash string
}{
	{"SETTLEMENT_SIGNER_ROLE", "0x9afba5c05b1dfbaa7188068a6610fc1a9f4c5b291aea74d5d9d8bc81f8d004f1"},
	{"PRODUCT_MANAGER_ROLE", "0x6393b9644ce4c807825084a6005494e3614c60e5c6b55898819660856eca231a"},
	{"COMMISSION_MANAGER_ROLE", "0xa5df0c1c8fbce806635da48fd7de12d5bae445b0768e07f5d4e7a67160524a11"},
}

func TestParseMerchantRole_HashesMatchTheContract(t *testing.T) {
	for _, tc := range roleVectors {
		t.Run(tc.name, func(t *testing.T) {
			role, err := parseMerchantRole(tc.name)
			if err != nil {
				t.Fatalf("parseMerchantRole(%q): %v", tc.name, err)
			}
			if got := hexRole(role); got != tc.hash {
				t.Fatalf("role hash = %s, want %s (MerchantRoles.sol)", got, tc.hash)
			}
		})
	}
}

func TestParseMerchantRole_AcceptsAnyCaseAndSurroundingSpace(t *testing.T) {
	for _, spelling := range []string{
		"settlement_signer_role", "  SETTLEMENT_SIGNER_ROLE  ", "Settlement_Signer_Role",
	} {
		role, err := parseMerchantRole(spelling)
		if err != nil {
			t.Fatalf("parseMerchantRole(%q): %v", spelling, err)
		}
		if got := hexRole(role); got != roleVectors[0].hash {
			t.Errorf("parseMerchantRole(%q) = %s, want the SETTLEMENT_SIGNER_ROLE hash", spelling, got)
		}
	}
}

// A role the contract does not allowlist reverts InvalidRole, which costs the agent a failed
// transaction to learn. Refusing it here makes the answer free, and names the alternatives.
func TestParseMerchantRole_RejectsUnknownRoleAndNamesTheValidOnes(t *testing.T) {
	for _, bad := range []string{"", "ADMIN", "DEFAULT_ADMIN_ROLE", "SETTLEMENT_SIGNER", "0x9afba5c0"} {
		_, err := parseMerchantRole(bad)
		if err == nil {
			t.Fatalf("parseMerchantRole(%q) accepted a role the contract would reject", bad)
		}
		for _, valid := range roleVectors {
			if !strings.Contains(err.Error(), valid.name) {
				t.Errorf("parseMerchantRole(%q) error does not mention %s: %v", bad, valid.name, err)
			}
		}
	}
}

// The bare constant is not the full role name. SETTLEMENT_SIGNER hashes to something else
// entirely, and a merchant granting it would hold a role the facilitator never checks — a
// silent no-op that looks like a successful grant.
func TestParseMerchantRole_BareNameIsNotTheRole(t *testing.T) {
	if _, err := parseMerchantRole("SETTLEMENT_SIGNER"); err == nil {
		t.Fatal("accepted SETTLEMENT_SIGNER: the role name carries the _ROLE suffix")
	}
}

func TestParseRoleAccount_RequiresA20ByteHexAddress(t *testing.T) {
	good, err := parseRoleAccount("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	if err != nil {
		t.Fatalf("parseRoleAccount: %v", err)
	}
	if got := good.Hex(); got != "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" {
		t.Fatalf("address = %s", got)
	}

	// A bare 40-hex-character address is accepted: the length is exact, so there is nothing to
	// pad or truncate and nothing a caller could have meant instead.
	if _, err := parseRoleAccount("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"); err != nil {
		t.Errorf("parseRoleAccount rejected an unambiguous unprefixed address: %v", err)
	}

	// go-ethereum's HexToAddress silently left-pads or truncates, so a wrong-length value
	// becomes a valid but DIFFERENT address — and a grant to it is a transaction that
	// succeeds, costs gas and delegates nothing. Each of these must be refused, not coerced.
	for _, bad := range []string{
		"", "0x",
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb922", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226666",
		"0xzzzzd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x0000000000000000000000000000000000000000",
	} {
		if _, err := parseRoleAccount(bad); err == nil {
			t.Errorf("parseRoleAccount(%q) accepted an address that cannot be what the caller meant", bad)
		}
	}
}
