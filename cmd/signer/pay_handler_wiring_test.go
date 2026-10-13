package main

import (
	"context"
	"crypto/ed25519"
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

// Call-site wiring for the pay path (REF-265).
//
// The helpers being correct proves nothing about the handler USING them: deleting the call leaves
// every helper test green with the feature dead. That is the bug class REF-270 §3 shipped, so this
// drives the real handlePayForProduct instead of the seam beneath it.
//
// Phase 2 is reachable without a chain — the RPC dial happens after it — so a fake merchant that
// 402s the payment POST lands exactly on the already-paid branch.

// payTestEnv stands up a merchant that answers the 402 probe with payment requirements and then
// fails the payment POST with body. Returns a ref link pointing at it.
func payTestEnv(t *testing.T, paymentStatus int, paymentBody string) string {
	t.Helper()
	refLink, _ := payTestEnvWith(t, merchantOpts{paymentStatus: paymentStatus, paymentBody: paymentBody})
	return refLink
}

// merchantOpts shapes the fake merchant's paid response.
type merchantOpts struct {
	paymentStatus      int
	paymentBody        string
	paymentContentType string
	paymentDelay       time.Duration
	// endpointQuery is appended to the merchant endpoint the token names, e.g. "?tier=a".
	endpointQuery string
}

// seenRequest is one call the merchant received at its endpoint.
type seenRequest struct {
	paid                                bool
	method, rawQuery, contentType, body string
}

// requestLog records the merchant's endpoint calls; the handler's requests arrive concurrently
// with the test goroutine.
type requestLog struct {
	mu   sync.Mutex
	reqs []seenRequest
}

func (l *requestLog) all() []seenRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]seenRequest(nil), l.reqs...)
}

func payTestEnvWith(t *testing.T, opts merchantOpts) (string, *requestLog) {
	t.Helper()
	log := &requestLog{}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate attestation key: %v", err)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/opensouk":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"attestationPubKey":"` + hexKey(pub) + `"}`))

		case r.URL.Path == "/buy" && r.Header.Get("PAYMENT-SIGNATURE") == "":
			log.record(r, false)
			// Phase 1: the 402 probe, answering with x402 payment requirements.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"x402Version": 2,
				"accepts": []map[string]any{{
					"scheme":            "exact",
					"network":           "eip155:84532",
					"amount":            "1000000",
					"asset":             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
					"payTo":             "0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E",
					"maxTimeoutSeconds": 600,
					"extra":             map[string]any{"name": "USDC", "version": "2"},
				}},
			})

		case r.URL.Path == "/buy":
			log.record(r, true)
			// Phase 2: the payment submission.
			time.Sleep(opts.paymentDelay)
			if opts.paymentContentType != "" {
				w.Header().Set("Content-Type", opts.paymentContentType)
			}
			w.WriteHeader(opts.paymentStatus)
			_, _ = w.Write([]byte(opts.paymentBody))

		case r.URL.Path == "/rpc":
			// Everything after phase 2 is three JSON-RPC calls: fetch the tx, wait for its
			// receipt, read the escrow id out of the EscrowDeposited log.
			serveStubRPC(t, w, r)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tok := validTestToken()
	tok.MerchantEndpoint = srv.URL + "/buy" + opts.endpointQuery
	tok.SetupURL = srv.URL + "/.well-known/opensouk"

	t.Setenv("BASE_RPC_URL", srv.URL+"/rpc")
	t.Setenv("CHAIN_ID", "84532")

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	prev := signerKeys
	signerKeys = &keystore{fallback: key}
	t.Cleanup(func() { signerKeys = prev })

	return srv.URL + "/r/" + signTestToken(t, priv, tok), log
}

func (l *requestLog) record(r *http.Request, paid bool) {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, seenRequest{
		paid: paid, method: r.Method, rawQuery: r.URL.RawQuery,
		contentType: r.Header.Get("Content-Type"), body: string(body),
	})
}

func hexKey(pub ed25519.PublicKey) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(pub)*2)
	for _, b := range pub {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}

// The load-bearing wiring test: a reused authorization must reach the caller as already_paid,
// through the real handler.
func TestPayForProduct_ReusedAuthorizationSurfacesAsAlreadyPaid(t *testing.T) {
	body := `{"error":"settle: route tx: Route tx: execution reverted: custom error ` +
		`0x3d22f6b8: 000000000000000000000000976ea74026e726554db657fa54763abd0c3a0aa9` +
		`a74bc243d5ab484ed80c7e59202d2f49916967baaf660b6693bd80906de8116c"}`
	refLink := payTestEnv(t, http.StatusPaymentRequired, body)

	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink:        refLink,
		AgentID:        "12",
		IdempotencyKey: "intent-abc",
	})
	if err == nil {
		t.Fatal("want an error when the facilitator rejects the payment")
	}
	if !strings.HasPrefix(err.Error(), alreadyPaidToken+":") {
		t.Fatalf("handler did not classify the reused authorization:\n%s\n\nThe helpers pass in "+
			"isolation, so this is the call site: a runner following REF-193 §C cannot match on "+
			"anything but the hex selector.", err)
	}
}

// Real Circle USDC words it differently, so the production rail is asserted too.
func TestPayForProduct_RealUSDCReuseSurfacesAsAlreadyPaid(t *testing.T) {
	body := `{"error":"settle: route tx: Route tx: execution reverted: ` +
		`FiatTokenV2: authorization is used or canceled"}`
	refLink := payTestEnv(t, http.StatusPaymentRequired, body)

	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink:        refLink,
		AgentID:        "12",
		IdempotencyKey: "intent-abc",
	})
	if err == nil || !strings.HasPrefix(err.Error(), alreadyPaidToken+":") {
		t.Fatalf("real-USDC reuse not classified:\n%v", err)
	}
}

// REF-364 moved the revert into the facilitator log; the merchant forwards only the reason.
func TestPayForProduct_FacilitatorAuthUsedReasonSurfacesAsAlreadyPaid(t *testing.T) {
	body := `{"success":false,"errorReason":"authorization_used","errorMessage":"this payment authorization was already used or cancelled; this request moved no funds"}`
	refLink := payTestEnv(t, http.StatusConflict, body)

	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink:        refLink,
		AgentID:        "12",
		IdempotencyKey: "intent-abc",
	})
	if err == nil || !strings.HasPrefix(err.Error(), alreadyPaidToken+":") {
		t.Fatalf("authorization_used reason not classified:\n%v", err)
	}
}

// Any other facilitator failure must keep the raw status and body. Classifying a genuine failure as
// a completed purchase would make a runner mark an unpaid intent executed.
func TestPayForProduct_OtherFailuresStayRaw(t *testing.T) {
	refLink := payTestEnv(t, http.StatusBadGateway, `{"error":"upstream unavailable"}`)

	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink,
		AgentID: "12",
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), alreadyPaidToken) {
		t.Fatalf("an unrelated failure was reported as already paid:\n%s", err)
	}
	if !strings.Contains(err.Error(), "upstream unavailable") {
		t.Errorf("the facilitator's body must survive:\n%s", err)
	}
}

// stubTxHash is the transaction the fake facilitator claims to have sent. Built once from a real
// signed tx so go-ethereum's own decoder accepts the RPC responses below.
var stubTx, stubTxErr = func() (*types.Transaction, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	to := common.HexToAddress("0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E")
	return types.SignTx(
		types.NewTx(&types.LegacyTx{Nonce: 1, To: &to, Gas: 21000, GasPrice: big.NewInt(1)}),
		types.NewEIP155Signer(big.NewInt(84532)), key,
	)
}()

// stubEscrowID is the id the EscrowDeposited log carries.
const stubEscrowID = 4242

// serveStubRPC answers the three eth_* calls the pay path makes after phase 2. It is deliberately
// minimal: this exists to reach the next_steps assignment, not to emulate a node.
func serveStubRPC(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if stubTxErr != nil {
		t.Fatalf("build stub tx: %v", stubTxErr)
	}

	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("stub rpc: bad request %s", body)
	}

	reply := func(result any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		})
	}

	switch req.Method {
	case "eth_getTransactionByHash":
		raw, err := stubTx.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal stub tx: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("remarshal stub tx: %v", err)
		}
		m["blockHash"] = common.HexToHash("0x01").Hex()
		m["blockNumber"] = "0x1"
		m["from"] = common.HexToAddress("0x02").Hex()
		reply(m)

	case "eth_getTransactionReceipt":
		receipt := &types.Receipt{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 21000,
			TxHash:            stubTx.Hash(),
			BlockHash:         common.HexToHash("0x01"),
			BlockNumber:       big.NewInt(1),
			Logs: []*types.Log{{
				Address: common.HexToAddress("0x03"),
				Topics: []common.Hash{
					escrowDepositedTopic,
					common.BigToHash(big.NewInt(stubEscrowID)),
				},
			}},
		}
		raw, err := receipt.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal stub receipt: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("remarshal stub receipt: %v", err)
		}
		reply(m)

	default:
		reply(nil)
	}
}

// paySucceeding drives the handler all the way through a successful purchase.
func paySucceeding(t *testing.T, agentID string) payForProductOutput {
	t.Helper()
	if stubTxErr != nil {
		t.Fatalf("build stub tx: %v", stubTxErr)
	}
	refLink := payTestEnv(t, http.StatusOK,
		`{"transaction":"`+stubTx.Hash().Hex()+`"}`)

	_, out, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink,
		AgentID: agentID,
	})
	if err != nil {
		t.Fatalf("handlePayForProduct(agent_id=%q): %v", agentID, err)
	}
	if out.EscrowID != "4242" {
		t.Fatalf("escrow_id = %q, want 4242 — the stub chain path did not run as expected", out.EscrowID)
	}
	return out
}

// The item-1 wiring test. next_steps was byte-identical on both paths, recommending a tool the
// agent-less caller cannot invoke; the helper being right proves nothing without this.
func TestPayForProduct_AgentLessNextStepsPointsAtBind(t *testing.T) {
	out := paySucceeding(t, "") // no agent_id → agent-less

	if out.NextSteps != payBindReminder {
		t.Fatalf("agent-less next_steps:\n%s\n\nwant the bind guidance. cast_review_votes requires "+
			"an agent_id this caller does not have, so the vote nudge cannot be followed.",
			out.NextSteps)
	}
}

func TestPayForProduct_AgentBoundNextStepsUnchanged(t *testing.T) {
	if out := paySucceeding(t, "12"); out.NextSteps != payVoteReminder {
		t.Fatalf("agent-bound next_steps changed:\n%s", out.NextSteps)
	}
}
