package main

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// The per-tool tables (bind, settle_fallback, update_review) already prove
// newRevertTable derives selectors correctly, since each of their tests looks up a
// selector it computed independently with keccak. What none of them reach are the shared
// mechanism's own guards, tested here: a selector that is simply absent, and a dataError
// whose ErrorData() is not the hex string go-ethereum returns. Both must degrade to
// ("", false) so the caller falls back to wrapping the raw error rather than reporting a
// confidently wrong reason — or panicking on a bad type assertion.

// fakeNonStringDataErr implements dataError but returns a non-string from ErrorData(),
// which is what a future or non-conforming RPC client could plausibly do.
type fakeNonStringDataErr struct{}

func (fakeNonStringDataErr) Error() string          { return "execution reverted" }
func (fakeNonStringDataErr) ErrorData() interface{} { return 42 }

// fakeBadHexDataErr implements dataError with revert data that is not valid hex.
type fakeBadHexDataErr struct{}

func (fakeBadHexDataErr) Error() string          { return "execution reverted" }
func (fakeBadHexDataErr) ErrorData() interface{} { return "0xnothex" }

func TestRevertTable_UnknownSelectorDoesNotDecode(t *testing.T) {
	table := newRevertTable(map[string]string{"Known(uint256)": "the known one"})

	known := crypto.Keccak256([]byte("Known(uint256)"))[:4]
	if msg, ok := table.lookupData(append(append([]byte{}, known...), make([]byte, 32)...)); !ok || msg != "the known one" {
		t.Fatalf("known selector: got ok=%v msg=%q, want true / %q", ok, msg, "the known one")
	}

	// A real selector from a DIFFERENT error must not match — a table must not answer for
	// errors it does not carry, or a caller would be handed advice for the wrong failure.
	other := crypto.Keccak256([]byte("Unknown(uint256)"))[:4]
	if _, ok := table.lookupData(append(append([]byte{}, other...), make([]byte, 32)...)); ok {
		t.Fatal("a selector absent from the table must not decode")
	}
}

func TestRevertTable_LookupErrRejectsMalformedData(t *testing.T) {
	sel := crypto.Keccak256([]byte("Known(uint256)"))[:4]
	table := newRevertTable(map[string]string{"Known(uint256)": "the known one"})

	// Sanity: the same table DOES decode a well-formed error, so the negative cases below
	// are rejecting the malformed input rather than failing for some unrelated reason.
	if _, ok := table.lookupErr(fakeEscrowRevertErr{data: "0x" + hex.EncodeToString(sel)}); !ok {
		t.Fatal("a well-formed revert error must decode")
	}

	if _, ok := table.lookupErr(fakeNonStringDataErr{}); ok {
		t.Fatal("ErrorData() returning a non-string must not decode")
	}
	if _, ok := table.lookupErr(fakeBadHexDataErr{}); ok {
		t.Fatal("revert data that is not valid hex must not decode")
	}
}
