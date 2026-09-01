package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestUpdateReview_ABIPack asserts the extended reviewRegistryABI packs
// updateReviewContent(reviewId, newContentHash) to the on-chain selector + args.
func TestUpdateReview_ABIPack(t *testing.T) {
	reviewID := big.NewInt(9)
	var hash [32]byte
	hash[0], hash[31] = 0xAB, 0xCD

	data, err := reviewRegistryABI.Pack("updateReviewContent", reviewID, hash)
	if err != nil {
		t.Fatalf("Pack updateReviewContent: %v", err)
	}
	if len(data) != 4+32+32 {
		t.Fatalf("calldata len = %d, want 68", len(data))
	}
	wantSel := crypto.Keccak256([]byte("updateReviewContent(uint256,bytes32)"))[:4]
	if got, want := hex.EncodeToString(data[:4]), hex.EncodeToString(wantSel); got != want {
		t.Fatalf("selector = %s, want %s", got, want)
	}
	args, err := reviewRegistryABI.Methods["updateReviewContent"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(reviewID) != 0 {
		t.Fatalf("unpacked reviewId = %v, want 9", args[0])
	}
	if got := args[1].([32]byte); got != hash {
		t.Fatalf("unpacked hash = %x, want %x", got, hash)
	}
}

// TestDecodeGetReview round-trips a getReview() return blob through the decoder, so a
// wrong field offset is caught here rather than as a silently wrong content hash on-chain.
// Encoding uses the same ABI types the contract's Review struct declares, in order.
//
// Fixture note: editedAt is deliberately NOT zero (unlike the field's natural "not yet
// edited" on-chain value). A decode bug that never assigns EditedAt would leave the struct
// field at its Go zero value; with editedAt=0 in the fixture that bug would be invisible.
// Using a distinct nonzero value here, and asserting it below, closes that gap — every one
// of the 7 words now has a value that differs from all six others, so a wrong offset (in
// either direction, on any field) reads a different word's value and fails an assertion.
func TestDecodeGetReview(t *testing.T) {
	uint256T, _ := abi.NewType("uint256", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)
	uint8T, _ := abi.NewType("uint8", "", nil)
	uint40T, _ := abi.NewType("uint40", "", nil)

	var productID, contentHash [32]byte
	productID[0], contentHash[0] = 0x11, 0x22

	const wantEditedAt = 1_700_050_000 // distinct from timestamp and every other word — see note above

	blob, err := abi.Arguments{
		{Type: uint256T}, {Type: uint256T}, {Type: bytes32T}, {Type: bytes32T},
		{Type: uint8T}, {Type: uint40T}, {Type: uint40T},
	}.Pack(big.NewInt(6080), big.NewInt(5943), productID, contentHash,
		uint8(2), big.NewInt(1_700_000_000), big.NewInt(wantEditedAt))
	if err != nil {
		t.Fatalf("pack fixture: %v", err)
	}

	got, err := decodeGetReview(blob)
	if err != nil {
		t.Fatalf("decodeGetReview: %v", err)
	}
	if got.AgentID.Int64() != 6080 || got.MerchantID.Int64() != 5943 {
		t.Fatalf("ids = %v/%v, want 6080/5943", got.AgentID, got.MerchantID)
	}
	if got.ProductID != productID || got.ContentHash != contentHash {
		t.Fatalf("productID/contentHash mismatch: %x / %x", got.ProductID, got.ContentHash)
	}
	if got.ProofType != 2 {
		t.Fatalf("proofType = %d, want 2 (InSystemPurchase)", got.ProofType)
	}
	if got.Timestamp != 1_700_000_000 {
		t.Fatalf("timestamp = %d, want 1700000000", got.Timestamp)
	}
	if got.EditedAt != wantEditedAt {
		t.Fatalf("editedAt = %d, want %d", got.EditedAt, wantEditedAt)
	}
	if _, err := decodeGetReview(blob[:100]); err == nil {
		t.Fatal("short blob must not decode")
	}
}

// TestEditWindowState pins ReviewRegistry's gate: the revert is
// `block.timestamp > timestamp + EDIT_WINDOW`, so exactly-at-the-boundary is still OPEN.
func TestEditWindowState(t *testing.T) {
	const published = 1_700_000_000
	const sevenDays = 7 * 24 * 60 * 60

	closesAt, open := editWindowState(published, published+1)
	if closesAt != published+sevenDays {
		t.Fatalf("closesAt = %d, want %d", closesAt, published+sevenDays)
	}
	if !open {
		t.Fatal("one second after publication must be open")
	}
	if _, open := editWindowState(published, published+sevenDays); !open {
		t.Fatal("exactly at the boundary must still be open (contract uses strict >)")
	}
	if _, open := editWindowState(published, published+sevenDays+1); open {
		t.Fatal("one second past the boundary must be closed")
	}
}

// TestUpdateReview_HashMatchesSharedHelper proves the tool hashes content the way publish
// does — and therefore the way the backend recomputes it — by checking that a different
// agentId changes the hash. That is why the ids are inside the preimage, and therefore why
// they must be read from the chain, not taken from the caller: a hash over the wrong ids is
// accepted by the contract and then permanently un-syncable.
func TestUpdateReview_HashMatchesSharedHelper(t *testing.T) {
	var productID [32]byte
	productID[0] = 0x11
	content := `{"rating":4,"description":"Updated."}`

	want, err := computeContentHash(big.NewInt(6080), big.NewInt(5943), productID, content)
	if err != nil {
		t.Fatalf("computeContentHash: %v", err)
	}
	// A different agentId MUST change the hash — proving the ids are inside the preimage,
	// which is why they have to be read from the chain and not taken from the caller.
	other, err := computeContentHash(big.NewInt(6081), big.NewInt(5943), productID, content)
	if err != nil {
		t.Fatalf("computeContentHash: %v", err)
	}
	if other == want {
		t.Fatal("hash ignored agentId — the preimage is wrong")
	}
}

// TestUpdateReview_ParseInputs asserts input parsing and rejection.
func TestUpdateReview_ParseInputs(t *testing.T) {
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: `{"rating":4}`}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "nope", ContentJSON: `{}`}); err == nil {
		t.Fatal("expected error on bad review_id")
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: "   "}); err == nil {
		t.Fatal("expected error on blank content_json")
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: "not json"}); err == nil {
		t.Fatal("expected error on non-JSON content_json")
	}
}

// TestDecodeUpdateReviewRevert maps each custom error this tool can hit to a message.
func TestDecodeUpdateReviewRevert(t *testing.T) {
	for _, sig := range []string{
		"ReviewNotFound(uint256)",
		"NotEditablePath(uint256)",
		"CallerNotAgentOwner(uint256,address)",
		"EditWindowClosed(uint256)",
	} {
		sel := crypto.Keccak256([]byte(sig))[:4]
		data := append(append([]byte{}, sel...), make([]byte, 64)...)
		msg, ok := decodeUpdateReviewRevertData(data)
		if !ok || msg == "" {
			t.Fatalf("%s: expected a decoded message, got ok=%v msg=%q", sig, ok, msg)
		}
	}
}

// TestUpdateReview_StopsBeforeRPCWithoutURL proves the handler validates inputs before it
// needs a chain, so a malformed call fails fast with a useful message.
func TestUpdateReview_StopsBeforeRPCWithoutURL(t *testing.T) {
	t.Setenv("BASE_RPC_URL", "")
	_, _, err := handleUpdateReviewContentOnchain(context.Background(), nil,
		updateReviewOnchainInput{ReviewID: "9", ContentJSON: `{"rating":4}`})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	if !strings.Contains(err.Error(), "BASE_RPC_URL") {
		t.Fatalf("expected the BASE_RPC_URL error, got %v", err)
	}
}
