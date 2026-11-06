package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// REF-562: a product registered at a template such as /letters/{id} is bought through a concrete
// url the agent passes. The signer checks the url fits the template on the product's own host,
// and that the facilitator's path rule resolves it to that product, before anything is signed.

func TestConcretePayURL(t *testing.T) {
	const tmpl = "https://m.example/letters/{id}"
	cases := []struct {
		name, registered, given string
		want                    string
		wantTemplated           bool
		wantErr                 string
	}{
		{"template without url", tmpl, "", "", false, "is a template"},
		{"template with a fitting url", tmpl, "https://m.example/letters/8812", "https://m.example/letters/8812", true, ""},
		{"host case, default port, trailing slash and query", tmpl, "https://M.EXAMPLE:443/letters/8812/?q=1", "https://M.EXAMPLE:443/letters/8812/?q=1", true, ""},
		{"another host", tmpl, "https://other.example/letters/8812", "", false, "not on the product's host"},
		{"another scheme", tmpl, "http://m.example/letters/8812", "", false, "not on the product's host"},
		{"another port", tmpl, "https://m.example:8443/letters/8812", "", false, "not on the product's host"},
		{"userinfo", tmpl, "https://u:p@m.example/letters/8812", "", false, "url"},
		{"not http", tmpl, "ftp://m.example/letters/8812", "", false, "url"},
		{"extra segment", tmpl, "https://m.example/letters/8812/raw", "", false, "does not fit"},
		{"encoded slash in the parameter", tmpl, "https://m.example/letters/a%2Fb", "", false, "url"},
		{"fixed without url", "https://m.example/buy", "", "https://m.example/buy", false, ""},
		{"fixed with the same path", "https://m.example/buy", "https://m.example/buy/", "https://m.example/buy/", false, ""},
		{"fixed with another path", "https://m.example/buy", "https://m.example/buy2", "", false, "does not fit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, templated, err := concretePayURL(tc.registered, tc.given)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %q, %v", tc.wantErr, got, err)
				}
				return
			}
			if err != nil || got != tc.want || templated != tc.wantTemplated {
				t.Fatalf("got %q templated=%v err=%v; want %q templated=%v", got, templated, err, tc.want, tc.wantTemplated)
			}
		})
	}
}

// catalogServer answers GET /v1/merchant/3/catalog with the given status and products.
func catalogServer(t *testing.T, status int, products []map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/merchant/3/catalog" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"products": products})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolvesToIntended(t *testing.T) {
	rpcTmpl := map[string]string{"product_id": siblingProductHex, "endpoint_url": "https://m.example/rpc/{network}"}
	rpcBase := map[string]string{"product_id": otherProductHex, "endpoint_url": "https://m.example/rpc/base"}
	cases := []struct {
		name     string
		status   int
		products []map[string]string
		payURL   string
		wantErr  string
	}{
		{"the template is the only match", 200, []map[string]string{rpcTmpl, rpcBase}, "https://m.example/rpc/eth?x=1", ""},
		{"another product's fixed path wins", 200, []map[string]string{rpcTmpl, rpcBase}, "https://m.example/rpc/base", "another product is registered"},
		{"overlapping templates", 200, []map[string]string{rpcTmpl, {"product_id": otherProductHex, "endpoint_url": "https://m.example/{a}/eth"}}, "https://m.example/rpc/eth", "url"},
		{"no listed product matches", 200, []map[string]string{rpcBase}, "https://m.example/rpc/eth", "url"},
		{"catalog not found", 404, nil, "https://m.example/rpc/eth", "cannot verify"},
		{"catalog failing", 500, nil, "https://m.example/rpc/eth", "cannot verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := catalogServer(t, tc.status, tc.products)
			err := resolvesToIntended(context.Background(), srv.Client(), srv.URL, "3", siblingProductHex, tc.payURL)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// templateEnv is a merchant whose token product lives at tokenPath and whose sibling lives at
// siblingPath (either may be a template), with the catalogue and public catalog served by the
// same fake. Unpaid calls answer 402 reporting the path called; paid calls stop with a 502.
func templateEnv(t *testing.T, tokenPath, siblingPath string) (string, func() []string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	hits := []string{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := r.Method + " " + r.URL.Path
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			h += " [paid]"
		}
		hits = append(hits, h)
		mu.Unlock()
		switch {
		case r.URL.Path == "/.well-known/opensouk":
			_, _ = w.Write([]byte(`{"attestationPubKey":"` + hexKey(pub) + `"}`))
		case r.URL.Path == "/v1/merchant/product":
			_, _ = w.Write([]byte(`{"active":true,"endpoint_url":"` + srv.URL + siblingPath + `"}`))
		case r.URL.Path == "/v1/merchant/3/catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"products": []map[string]string{
				{"product_id": tokenProductHex, "endpoint_url": srv.URL + tokenPath},
				{"product_id": siblingProductHex, "endpoint_url": srv.URL + siblingPath},
			}})
		case r.Header.Get("PAYMENT-SIGNATURE") == "":
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"x402Version": 2,
				"accepts": []map[string]any{{
					"scheme": "exact", "network": "eip155:84532", "amount": "1000000",
					"asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
					"payTo": "0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E", "maxTimeoutSeconds": 600,
					"extra": map[string]any{"name": "USDC", "version": "2", "endpoint": r.URL.Path},
				}},
			})
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"stop here"}`))
		}
	}))
	t.Cleanup(srv.Close)

	tok := validTestToken()
	tok.MerchantEndpoint = srv.URL + tokenPath
	t.Setenv("BASE_RPC_URL", srv.URL+"/rpc")
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("ATTESTATION_ORIGIN", srv.URL)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	prev := signerKeys
	signerKeys = &keystore{fallback: newLocalSigner(key)}
	t.Cleanup(func() { signerKeys = prev })

	return srv.URL + "/r/" + signTestToken(t, priv, tok), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), hits...)
	}
}

func merchantHits(hits []string) []string {
	var out []string
	for _, h := range hits {
		if !strings.Contains(h, "/.well-known/") && !strings.Contains(h, "/v1/merchant/") {
			out = append(out, h)
		}
	}
	return out
}

func TestPayForProduct_TemplatedSibling_PaysTheGivenURL(t *testing.T) {
	refLink, hits := templateEnv(t, "/buy", "/letters/{id}")
	base := strings.SplitN(refLink, "/r/", 2)[0]
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex, URL: base + "/letters/7",
	})
	if err == nil || !strings.Contains(err.Error(), "stop here") {
		t.Fatalf("expected to reach phase 2 at /letters/7 and stop there, got %v", err)
	}
	seen := strings.Join(hits(), "\n") + "\n"
	for _, want := range []string{"GET /v1/merchant/3/catalog", "POST /letters/7\n", "POST /letters/7 [paid]"} {
		if !strings.Contains(seen, want) {
			t.Errorf("missing %q in requests:\n%s", want, seen)
		}
	}
}

func TestPayForProduct_TemplatedSibling_NoURL_Refused(t *testing.T) {
	refLink, hits := templateEnv(t, "/buy", "/letters/{id}")
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex,
	})
	if err == nil || !strings.Contains(err.Error(), "is a template") {
		t.Fatalf("want a refusal asking for url, got %v", err)
	}
	if m := merchantHits(hits()); len(m) != 0 {
		t.Fatalf("the merchant must not be called: %v", m)
	}
}

func TestPayForProduct_TemplatedTokenProduct_NoURL_Refused(t *testing.T) {
	refLink, hits := templateEnv(t, "/letters/{id}", "/buy-b")
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{RefLink: refLink, AgentID: "12"})
	if err == nil || !strings.Contains(err.Error(), "is a template") {
		t.Fatalf("want a refusal asking for url, got %v", err)
	}
	if m := merchantHits(hits()); len(m) != 0 {
		t.Fatalf("the merchant must not be called: %v", m)
	}
}

func TestPayForProduct_URLQueryClashesWithRequestQuery_Refused(t *testing.T) {
	refLink, hits := templateEnv(t, "/buy", "/letters/{id}")
	base := strings.SplitN(refLink, "/r/", 2)[0]
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex, URL: base + "/letters/7?lang=en",
		Request: &payRequest{Query: map[string]string{"lang": "de"}},
	})
	if err == nil || !strings.Contains(err.Error(), "already sets it") {
		t.Fatalf("want the query clash refused, got %v", err)
	}
	if m := merchantHits(hits()); len(m) != 0 {
		t.Fatalf("the merchant must not be called: %v", m)
	}
}

// The link's own product is registered at the fixed /letters/latest; the sibling at the template
// /letters/{id}. Paying the sibling at /letters/latest would settle as the link's product, so it
// is refused before the merchant is called.
func TestPayForProduct_TemplatedSibling_FixedPathOfAnotherProduct_Refused(t *testing.T) {
	refLink, hits := templateEnv(t, "/letters/latest", "/letters/{id}")
	base := strings.SplitN(refLink, "/r/", 2)[0]
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex, URL: base + "/letters/latest",
	})
	if err == nil || !strings.Contains(err.Error(), "another product is registered") {
		t.Fatalf("want a refusal naming the fixed path, got %v", err)
	}
	if m := merchantHits(hits()); len(m) != 0 {
		t.Fatalf("the merchant must not be called: %v", m)
	}
}
