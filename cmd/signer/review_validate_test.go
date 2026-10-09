package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The validate endpoint's reply for content the backend refuses, as the REF-469 handler writes it.
const refusedReply = `{"valid":false,"rule":"schema","path":"","error":"content_json: schema: /core: missing properties: 'price_paid_usdc'"}`

const (
	testAgent     = 5
	testMerchant  = 2
	testRegistry  = "0x00000000000000000000000000000000000000aa"
	testEscrowSC  = "0x00000000000000000000000000000000000000bb"
	testReviewID  = 9
	testEscrowID  = 4
	oldStoredHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
)

var testProduct = [32]byte{31: 0x07}

// stubChain answers the eth_* calls both review tools make, records every method it is
// asked, and captures the calldata of the first eth_estimateGas, which it then refuses — the
// tool stops there with the hash it would have sent in hand.
type stubChain struct {
	mu        sync.Mutex
	methods   []string
	estimated []byte
}

func (s *stubChain) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...)
}

func serveStubChain(t *testing.T) *stubChain {
	t.Helper()
	s := &stubChain{}
	now := time.Now().Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("stub chain: bad request %s", body)
			return
		}
		s.mu.Lock()
		s.methods = append(s.methods, req.Method)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		reply := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		}
		var call struct {
			To    string `json:"to"`
			Data  string `json:"data"`
			Input string `json:"input"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params[0], &call)
		}
		switch req.Method {
		case "eth_call":
			if strings.EqualFold(call.To, testEscrowSC) {
				reply("0x" + hex.EncodeToString(escrowBlob()))
			} else {
				reply("0x" + hex.EncodeToString(reviewBlob(now-100)))
			}
		case "eth_getBlockByNumber":
			h := &types.Header{Number: big.NewInt(1), Time: uint64(now), BaseFee: big.NewInt(1), Difficulty: big.NewInt(0)}
			reply(h)
		case "eth_getTransactionCount", "eth_maxPriorityFeePerGas", "eth_gasPrice":
			reply("0x1")
		case "eth_getCode":
			reply("0x60")
		case "eth_estimateGas":
			data := call.Input
			if data == "" {
				data = call.Data
			}
			raw, _ := hex.DecodeString(strings.TrimPrefix(data, "0x"))
			s.mu.Lock()
			if s.estimated == nil {
				s.estimated = raw
			}
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32000, "message": "stub: stop before send"}})
		default:
			reply(nil)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("BASE_RPC_URL", srv.URL)
	t.Setenv("REVIEW_REGISTRY_ADDRESS", testRegistry)
	t.Setenv("COMMISSION_ESCROW_ADDRESS", testEscrowSC)
	return s
}

func escrowBlob() []byte {
	raw := make([]byte, escrowRecordWords*32)
	copy(word(raw, 1), common.BigToHash(big.NewInt(testAgent)).Bytes())
	copy(word(raw, 4), common.BigToHash(big.NewInt(testMerchant)).Bytes())
	copy(word(raw, 5), testProduct[:])
	return raw
}

func reviewBlob(publishedAt int64) []byte {
	raw := make([]byte, 7*32)
	copy(raw[0:32], common.BigToHash(big.NewInt(testAgent)).Bytes())
	copy(raw[32:64], common.BigToHash(big.NewInt(testMerchant)).Bytes())
	copy(raw[64:96], testProduct[:])
	copy(raw[96:128], common.HexToHash(oldStoredHash).Bytes())
	copy(raw[128:160], common.BigToHash(big.NewInt(int64(proofTypeInSystemPurchase))).Bytes())
	copy(raw[160:192], common.BigToHash(big.NewInt(publishedAt)).Bytes())
	return raw
}

// useAgentKey installs a signer key for testAgent and points the tools at the backend.
func useAgentKey(t *testing.T, backend string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := parseKeystore("5:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatal(err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })
	t.Setenv("REFERRER_API_URL", backend)
}

// signedHash is the content hash the tool put in the calldata it tried to send: the second
// word of both publishReviewWithEscrowProof(agentId, contentHash, escrowId) and
// updateReviewContent(reviewId, contentHash).
func signedHash(t *testing.T, calldata []byte) common.Hash {
	t.Helper()
	if len(calldata) < 4+64 {
		t.Fatalf("no transaction calldata was captured (%d bytes)", len(calldata))
	}
	return common.BytesToHash(calldata[4+32 : 4+64])
}

func publishIn(content string) publishEscrowReviewInput {
	return publishEscrowReviewInput{
		AgentID: "5", MerchantID: "2", EscrowID: "4",
		ProductID: "0x" + hex.EncodeToString(testProduct[:]), ContentJSON: content,
	}
}

func TestCheckReviewContent_SendsTheReviewAsGiven(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"valid":true}`, &got)
	t.Setenv("REFERRER_API_URL", srv.URL)

	if err := checkReviewContent(context.Background(), big.NewInt(0), big.NewInt(testMerchant), testProduct, v1Review, nil); err != nil {
		t.Fatalf("valid content refused: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/v1/review/validate" {
		t.Fatalf("asked %s %s, want POST /v1/review/validate", got.method, got.path)
	}
	var body map[string]any
	if err := json.Unmarshal(got.body, &body); err != nil {
		t.Fatal(err)
	}
	// agent_id 0 is a real agent: it must be sent, not dropped as a zero value.
	if body["agent_id"] != float64(0) || body["merchant_id"] != float64(testMerchant) ||
		body["product_id"] != "0x"+hex.EncodeToString(testProduct[:]) || body["content_json"] != v1Review {
		t.Fatalf("request body = %s", got.body)
	}
}

func TestCheckReviewContent_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		status int
		reply  string
		want   string
	}{
		{"refused content", http.StatusOK, refusedReply, "missing properties: 'price_paid_usdc'"},
		{"server error", http.StatusInternalServerError, `{"error":"boom"}`, "status 500: boom"},
		{"unknown product", http.StatusNotFound, `{"error":"product not found"}`, "status 404"},
		{"no verdict", http.StatusOK, `{}`, "could not read"},
	} {
		var got capturedRequest
		t.Setenv("REFERRER_API_URL", fakeBackend(t, tc.status, tc.reply, &got).URL)
		err := checkReviewContent(context.Background(), big.NewInt(testAgent), big.NewInt(testMerchant), testProduct, v1Review, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing was") {
			t.Errorf("%s: err = %v, want a refusal containing %q", tc.desc, err, tc.want)
		}
	}

	t.Setenv("REFERRER_API_URL", "http://127.0.0.1:1")
	if err := checkReviewContent(context.Background(), big.NewInt(testAgent), big.NewInt(testMerchant), testProduct, v1Review, nil); err == nil {
		t.Error("an unreachable backend let the content through")
	}
}

func TestPublishEscrowReview_RefusesInvalidContentBeforeTheChain(t *testing.T) {
	chain := serveStubChain(t)
	var got capturedRequest
	useAgentKey(t, fakeBackend(t, http.StatusOK, refusedReply, &got).URL)

	_, _, err := handlePublishEscrowReview(context.Background(), nil, publishIn(v1Review))
	if err == nil || !strings.Contains(err.Error(), "missing properties: 'price_paid_usdc'") {
		t.Fatalf("err = %v, want the backend's refusal", err)
	}
	if calls := chain.called(); len(calls) != 0 {
		t.Fatalf("refused content still reached the chain: %v", calls)
	}
	if !bytes.Contains(got.body, []byte(`"agent_id":5`)) {
		t.Fatalf("the dry-run was not given the agent, so a cited proof went unbound: %s", got.body)
	}
	if bytes.Contains(got.body, []byte(`"review_id"`)) {
		t.Fatalf("a new review's dry-run named a review id: %s", got.body)
	}
}

func TestPublishEscrowReview_ValidContentIsHashedAsGiven(t *testing.T) {
	chain := serveStubChain(t)
	var got capturedRequest
	useAgentKey(t, fakeBackend(t, http.StatusOK, `{"valid":true}`, &got).URL)

	_, _, err := handlePublishEscrowReview(context.Background(), nil, publishIn(v1Review))
	if err == nil || !strings.Contains(err.Error(), "stop before send") {
		t.Fatalf("err = %v, want the stub chain's stop at the send", err)
	}
	want, _ := computeContentHash(big.NewInt(testAgent), big.NewInt(testMerchant), testProduct, v1Review)
	if signedHash(t, chain.estimated) != want {
		t.Fatal("the hash sent is not over the content exactly as given")
	}
}

func TestUpdateReviewOnchain_RefusesInvalidContentBeforeSigning(t *testing.T) {
	chain := serveStubChain(t)
	var got capturedRequest
	useAgentKey(t, fakeBackend(t, http.StatusOK, refusedReply, &got).URL)

	_, _, err := handleUpdateReviewContentOnchain(context.Background(), nil,
		updateReviewOnchainInput{ReviewID: "9", ContentJSON: v1Review})
	if err == nil || !strings.Contains(err.Error(), "missing properties: 'price_paid_usdc'") {
		t.Fatalf("err = %v, want the backend's refusal", err)
	}
	// The review is read first — its ids are what the content is checked against — but no
	// transaction is built.
	for _, m := range chain.called() {
		if m != "eth_call" && m != "eth_getBlockByNumber" {
			t.Fatalf("refused content went past the reads: %v", chain.called())
		}
	}
	if !bytes.Contains(got.body, []byte(`"agent_id":5`)) || !bytes.Contains(got.body, []byte(`"merchant_id":2`)) {
		t.Fatalf("the dry-run was not given the on-chain ids: %s", got.body)
	}
	// The edited review's id, so its own onchain_receipts do not count as reused (REF-425).
	if !bytes.Contains(got.body, []byte(`"review_id":9`)) {
		t.Fatalf("the edit's dry-run did not name the review: %s", got.body)
	}
}

func TestUpdateReviewOnchain_ValidContentIsHashedAsGiven(t *testing.T) {
	chain := serveStubChain(t)
	var got capturedRequest
	useAgentKey(t, fakeBackend(t, http.StatusOK, `{"valid":true}`, &got).URL)

	_, _, err := handleUpdateReviewContentOnchain(context.Background(), nil,
		updateReviewOnchainInput{ReviewID: "9", ContentJSON: v1Review})
	if err == nil || !strings.Contains(err.Error(), "stop before send") {
		t.Fatalf("err = %v, want the stub chain's stop at the send", err)
	}
	want, _ := computeContentHash(big.NewInt(testAgent), big.NewInt(testMerchant), testProduct, v1Review)
	if signedHash(t, chain.estimated) != want {
		t.Fatal("the hash sent is not over the content exactly as given")
	}
}
