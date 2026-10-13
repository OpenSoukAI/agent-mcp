package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The paid response is the product the agent bought. These drive the real handler: a helper that
// captures the response proves nothing if the handler never returns what it captured.

func paidBody(extra string) string {
	return `{"transaction":"` + stubTx.Hash().Hex() + `"` + extra + `}`
}

func payWith(t *testing.T, opts merchantOpts, req *payRequest) (payForProductOutput, *requestLog, error) {
	t.Helper()
	if stubTxErr != nil {
		t.Fatalf("build stub tx: %v", stubTxErr)
	}
	if opts.paymentStatus == 0 {
		opts.paymentStatus = http.StatusOK
	}
	refLink, log := payTestEnvWith(t, opts)
	_, out, err := handlePayForProduct(context.Background(), nil, payForProductInput{RefLink: refLink, AgentID: "12", Request: req})
	return out, log, err
}

func TestPayForProduct_ReturnsWhatTheMerchantServed(t *testing.T) {
	body := paidBody(`,"resource":{"block":"0x2dca1e1"}`)
	out, _, err := payWith(t, merchantOpts{paymentBody: body, paymentContentType: "application/json", paymentDelay: 40 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	if out.Response != body {
		t.Errorf("response = %q, want the merchant's body %q", out.Response, body)
	}
	if out.ResponseBytes != len(body) || out.ResponseTruncated {
		t.Errorf("response_bytes = %d truncated = %v, want %d and false", out.ResponseBytes, out.ResponseTruncated, len(body))
	}
	if out.ContentType != "application/json" {
		t.Errorf("content_type = %q, want application/json", out.ContentType)
	}
	// The merchant sleeps 40ms before answering the PAID call, so a latency of less than that was
	// not taken around it.
	if out.LatencyMS < 40 {
		t.Errorf("latency_ms = %d, want >= 40: the paid request was not timed", out.LatencyMS)
	}
}

func TestPayForProduct_TruncatesALargeResponseButReportsItsSize(t *testing.T) {
	// The "x" puts the cut at an odd offset into the two-byte "é"s, so it lands mid-character and
	// the valid-UTF-8 check below can catch a byte-level cut.
	body := paidBody(`,"resource":"x` + strings.Repeat("é", maxResponseBytes) + `"`)
	if utf8.RuneStart(body[maxResponseBytes]) {
		t.Fatal("fixture: the cut must land mid-character or this test cannot see a split rune")
	}
	out, _, err := payWith(t, merchantOpts{paymentBody: body}, nil)
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	if !out.ResponseTruncated || len(out.Response) > maxResponseBytes {
		t.Fatalf("response %d bytes truncated=%v, want at most %d and true", len(out.Response), out.ResponseTruncated, maxResponseBytes)
	}
	if out.ResponseBytes != len(body) {
		t.Errorf("response_bytes = %d, want the full %d", out.ResponseBytes, len(body))
	}
	if !strings.HasPrefix(body, out.Response) || !utf8.ValidString(out.Response) {
		t.Error("the truncated response must be a valid-UTF-8 prefix of the body")
	}
}

func TestTruncateUTF8_NeverSplitsARune(t *testing.T) {
	for _, c := range []struct {
		in, want string
		max      int
		cut      bool
	}{
		{"aé", "a", 2, true}, // é is 2 bytes; byte 2 is its second half
		{"aé", "aé", 3, false},
		{"aé", "aé", 10, false},
		{"", "", 0, false},
	} {
		got, cut := truncateUTF8(c.in, c.max)
		if got != c.want || cut != c.cut {
			t.Errorf("truncateUTF8(%q, %d) = %q, %v; want %q, %v", c.in, c.max, got, cut, c.want, c.cut)
		}
	}
}

// The probe quotes the price for the request it is sent, so it must be the request then paid for.
func TestPayForProduct_SendsTheAgentsRequestToProbeAndPayment(t *testing.T) {
	rpc := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	_, log, err := payWith(t, merchantOpts{paymentBody: paidBody("")},
		&payRequest{Method: "POST", Body: rpc, ContentType: "application/json", Query: map[string]string{"network": "base-sepolia"}})
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	assertBothPhases(t, log, seenRequest{method: "POST", body: rpc, contentType: "application/json", rawQuery: "network=base-sepolia"})
}

func TestPayForProduct_GETCarriesQueryAndNoBody(t *testing.T) {
	_, log, err := payWith(t, merchantOpts{paymentBody: paidBody("")},
		&payRequest{Method: "get", Query: map[string]string{"q": "opensouk agents"}})
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	assertBothPhases(t, log, seenRequest{method: "GET", rawQuery: "q=opensouk+agents"})
}

// Pinned: a caller passing no request must see exactly today's wire behaviour.
func TestPayForProduct_NoRequestSendsTheEmptyJSONPOSTAsBefore(t *testing.T) {
	_, log, err := payWith(t, merchantOpts{paymentBody: paidBody("")}, nil)
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	assertBothPhases(t, log, seenRequest{method: "POST", body: "{}", contentType: "application/json"})
}

// A malformed request must fail before the merchant hears anything, so nothing is paid for it.
func TestPayForProduct_RejectsABadRequestBeforeContactingTheMerchant(t *testing.T) {
	for name, c := range map[string]struct {
		req      *payRequest
		endpoint string
		wantErr  string
	}{
		"unsupported method":      {req: &payRequest{Method: "PUT"}, wantErr: "method"},
		"GET with a body":         {req: &payRequest{Method: "GET", Body: "{}"}, wantErr: "body"},
		"GET with a content type": {req: &payRequest{Method: "GET", ContentType: "text/plain"}, wantErr: "content_type"},
		"query overrides the merchant's own": {
			req: &payRequest{Query: map[string]string{"tier": "b"}}, endpoint: "?tier=a", wantErr: "tier",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, log, err := payWith(t, merchantOpts{paymentBody: paidBody(""), endpointQuery: c.endpoint}, c.req)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, c.wantErr)
			}
			if got := log.all(); len(got) != 0 {
				t.Fatalf("the merchant received %d request(s); a rejected request must send none", len(got))
			}
		})
	}
}

func assertBothPhases(t *testing.T, log *requestLog, want seenRequest) {
	t.Helper()
	got := log.all()
	if len(got) != 2 || got[0].paid || !got[1].paid {
		t.Fatalf("merchant saw %+v, want the probe then the paid request", got)
	}
	for i, phase := range []string{"probe", "paid request"} {
		g := got[i]
		g.paid = false
		if g != want {
			t.Errorf("%s = %+v, want %+v", phase, g, want)
		}
	}
}
