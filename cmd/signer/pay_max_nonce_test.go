package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// REF-193 A: pay_for_product must refuse when the live merchant price exceeds
// the owner-confirmed max_amount, and must not otherwise interfere.
func TestEnforceMaxAmount(t *testing.T) {
	tests := []struct {
		name    string
		live    string
		max     string
		wantErr string // substring; "" = expect no error
	}{
		{"empty max skips cap", "1000000", "", ""},
		{"under max ok", "900000", "1000000", ""},
		{"equal max ok", "1000000", "1000000", ""},
		{"over max refused", "1000001", "1000000", "exceeds approved max_amount"},
		{"way over refused", "5000000", "1000000", "exceeds approved max_amount"},
		{"malformed live", "abc", "1000000", "invalid live amount"},
		{"malformed max", "1000000", "1e6", "invalid max_amount"},
		{"negative max malformed treated as invalid", "1000000", "-1", "exceeds approved max_amount"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := enforceMaxAmount(tt.live, tt.max)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("enforceMaxAmount(%q,%q) = %v, want nil", tt.live, tt.max, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("enforceMaxAmount(%q,%q) = %v, want err containing %q", tt.live, tt.max, err, tt.wantErr)
			}
		})
	}
}

// REF-193 B: the ERC-3009 nonce derived from (payer, idempotency_key) must be
// deterministic (so a retry of the same intent reuses the nonce and the second
// receiveWithAuthorization reverts — at-most-once), and must match
// keccak256(payer ‖ idempotency_key).
func TestDeriveNonce(t *testing.T) {
	payer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	other := common.HexToAddress("0x2222222222222222222222222222222222222222")
	key := "intent-abc-123"

	got := deriveNonce(payer, key)

	// deterministic: same inputs → same nonce
	if again := deriveNonce(payer, key); again != got {
		t.Fatalf("deriveNonce not deterministic: %x != %x", again, got)
	}

	// matches hand-computed keccak256(payer ‖ key)
	want := crypto.Keccak256(append(payer.Bytes(), []byte(key)...))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("deriveNonce = %x, want keccak256(payer‖key) = %x", got, want)
	}

	// key-sensitive: a different idempotency key → different nonce
	if diff := deriveNonce(payer, "intent-xyz-999"); diff == got {
		t.Fatalf("deriveNonce collided across different keys: %x", diff)
	}

	// payer-sensitive: a different payer → different nonce
	if diff := deriveNonce(other, key); diff == got {
		t.Fatalf("deriveNonce collided across different payers: %x", diff)
	}
}
