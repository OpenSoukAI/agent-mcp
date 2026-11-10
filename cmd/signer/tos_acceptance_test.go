package main

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// testdata/tos_acceptance_vectors.json is copied from backend internal/signing (backend#388). It
// pins the frozen type: if this signer's digest drifts from it, the backend rejects every signature.
func TestTosAcceptance_BackendVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/tos_acceptance_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		TypeString string `json:"typeString"`
		SignerKey  string `json:"signerKey"`
		Vectors    []struct {
			Name, Role, IdentityID, TosVersion, TosSource, NameOnFile, EmailOnFile, Statement string
			ChainID                                                                           int64
			SignedAt                                                                          uint64
			TosHash, NameEmailHash, Digest, Signature, Signer                                 string
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.TypeString != tosTypeString {
		t.Fatalf("type string drifted from the backend: %q vs %q", tosTypeString, f.TypeString)
	}
	key, _ := crypto.HexToECDSA(strings.TrimPrefix(f.SignerKey, "0x"))
	for _, v := range f.Vectors {
		id, _ := new(big.Int).SetString(v.IdentityID, 10)
		m := tosMessage{Role: v.Role, IdentityID: id, TosVersion: v.TosVersion, Statement: v.Statement, SignedAt: v.SignedAt,
			TosHash: crypto.Keccak256Hash([]byte(v.TosSource))}
		if v.Role == "merchant" {
			m.NameEmailHash = tosNameEmailHash(v.NameOnFile, v.EmailOnFile)
		}
		if hexutil.Encode(m.TosHash[:]) != v.TosHash || hexutil.Encode(m.NameEmailHash[:]) != v.NameEmailHash {
			t.Errorf("%s: hashes drifted", v.Name)
		}
		want, _ := tosDigest(m, v.ChainID)
		if hexutil.Encode(want) != v.Digest {
			t.Errorf("%s: digest %x, backend %s", v.Name, want, v.Digest)
			continue
		}
		// The same path the tool signs with: typed data checked against the digest, v as 27/28.
		sig, err := signTos(context.Background(), newLocalSigner(key), m, v.ChainID)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if hexutil.Encode(sig) != v.Signature {
			t.Errorf("%s: signature %x, backend %s", v.Name, sig, v.Signature)
		}
	}
}

// tosBackend fakes GET /v1/tos/current and POST /v1/tos/acceptance and records the POST.
type tosBackend struct {
	chainID   int64
	current   string // JSON body for /current; "" answers 404
	postCode  int
	postReply string
	posted    *capturedRequest
	posts     int
}

func (b *tosBackend) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tos/current":
			if r.URL.Query().Get("chain_id") == "" {
				t.Errorf("GET /current without chain_id")
			}
			if b.current == "" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"no merchant ToS version is in force","code":"not_published"}`))
				return
			}
			_, _ = w.Write([]byte(b.current))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tos/acceptance":
			b.posts++
			body, _ := io.ReadAll(r.Body)
			*b.posted = capturedRequest{method: r.Method, path: r.URL.Path + "?" + r.URL.RawQuery, body: body, header: r.Header.Clone()}
			w.WriteHeader(b.postCode)
			_, _ = w.Write([]byte(b.postReply))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const tosCurrentJSON = `{"role":"merchant","version":"1.0","hash":"0x0707070707070707070707070707070707070707070707070707070707070707",
 "url":"https://opensouk.ai/legal/merchant-terms/v1.0","statement":"I accept the OpenSouk Merchant Terms of Use v1.0 · Privacy notice: opensouk.ai/legal/privacy",
 "effective_at":"2026-11-01T00:00:00Z","chain_id":84532,
 "upcoming":{"version":"2.0","hash":"0x2222222222222222222222222222222222222222222222222222222222222222","url":"https://opensouk.ai/legal/merchant-terms/v2.0",
  "statement":"I accept the OpenSouk Merchant Terms of Use v2.0 · Privacy notice: opensouk.ai/legal/privacy","effective_at":"2026-12-01T00:00:00Z"}}`

func newTosFixture(t *testing.T, b *tosBackend) (*capturedRequest, *big.Int) {
	t.Helper()
	got := &capturedRequest{}
	b.posted = got
	if b.postCode == 0 {
		b.postCode = http.StatusCreated
		b.postReply = `{"id":1,"role":"merchant","identity_id":42,"signer":"0xabc","tos_status":"accepted","can_trade":true,"upcoming_version":null,"sign_by":null}`
	}
	srv := b.serve(t)
	useFakeBackend(t, srv, "42")
	t.Setenv("CHAIN_ID", "84532")
	return got, big.NewInt(42)
}

func merchantTosInput(accept string) signTosAcceptanceInput {
	return signTosAcceptanceInput{Role: "merchant", IdentityID: "42", ContactName: "Acme Ltd", ContactEmail: "legal@acme.example", AcceptVersion: accept}
}

// The first call is for the user's eyes only: it must not sign or send anything.
func TestSignTos_PreviewSignsNothing(t *testing.T) {
	b := &tosBackend{current: tosCurrentJSON}
	newTosFixture(t, b)
	_, out, err := handleSignTosAcceptance(context.Background(), nil, merchantTosInput(""))
	if err != nil {
		t.Fatal(err)
	}
	if b.posts != 0 {
		t.Fatalf("preview POSTed %d acceptances", b.posts)
	}
	if out.Status != "preview" || out.Current == nil || out.Current.Version != "1.0" || out.Upcoming == nil || out.Upcoming.Version != "2.0" ||
		!strings.Contains(out.Next, "ask whether they accept") {
		t.Errorf("preview: %+v", out)
	}
}

// accepted_version selects which published text is signed; the signature recovers to this key
// over exactly the backend's digest, and the POST carries what the backend checks.
func TestSignTos_AcceptSignsTheChosenVersion(t *testing.T) {
	for _, tc := range []struct{ version, hash, statement string }{
		{"1.0", "0x0707070707070707070707070707070707070707070707070707070707070707", "I accept the OpenSouk Merchant Terms of Use v1.0 · Privacy notice: opensouk.ai/legal/privacy"},
		{"2.0", "0x2222222222222222222222222222222222222222222222222222222222222222", "I accept the OpenSouk Merchant Terms of Use v2.0 · Privacy notice: opensouk.ai/legal/privacy"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			b := &tosBackend{current: tosCurrentJSON}
			got, id := newTosFixture(t, b)
			_, out, err := handleSignTosAcceptance(context.Background(), nil, merchantTosInput(tc.version))
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != "accepted" || out.SignedVersion != tc.version || out.TosStatus != "accepted" || out.CanTrade == nil || !*out.CanTrade {
				t.Errorf("out: %+v", out)
			}
			if got.path != "/v1/tos/acceptance?chain_id=84532" {
				t.Errorf("path %q", got.path)
			}
			var body struct {
				Role         string `json:"role"`
				IdentityID   int64  `json:"identity_id"`
				TosVersion   string `json:"tos_version"`
				SignedAt     uint64 `json:"signed_at"`
				Signature    string `json:"signature"`
				ContactName  string `json:"contact_name"`
				ContactEmail string `json:"contact_email"`
			}
			if err := json.Unmarshal(got.body, &body); err != nil {
				t.Fatal(err)
			}
			if body.Role != "merchant" || body.IdentityID != 42 || body.TosVersion != tc.version ||
				body.ContactName != "Acme Ltd" || body.ContactEmail != "legal@acme.example" {
				t.Errorf("body: %+v", body)
			}
			if d := time.Since(time.Unix(int64(body.SignedAt), 0)); d < 0 || d > time.Minute {
				t.Errorf("signed_at %d is not now", body.SignedAt)
			}
			var h [32]byte
			copy(h[:], hexutil.MustDecode(tc.hash))
			digest, _ := tosDigest(tosMessage{Role: "merchant", IdentityID: id, TosVersion: tc.version, TosHash: h,
				NameEmailHash: tosNameEmailHash("Acme Ltd", "legal@acme.example"), Statement: tc.statement, SignedAt: body.SignedAt}, 84532)
			sig := hexutil.MustDecode(body.Signature)
			if sig[64] >= 27 {
				sig[64] -= 27
			}
			pub, err := crypto.SigToPub(digest, sig)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := signerKeys.KeyFor("42")
			if crypto.PubkeyToAddress(*pub) != key.Address() {
				t.Error("signature does not recover to the signer key over the backend's digest")
			}
			assertSignedFor(t, *got, key.Address().Hex())
		})
	}
}

func TestSignTos_Refusals(t *testing.T) {
	cases := map[string]struct {
		in      signTosAcceptanceInput
		current string
		want    string
	}{
		"version nobody showed":        {merchantTosInput("3.0"), tosCurrentJSON, "nothing was signed"},
		"merchant without contact":     {signTosAcceptanceInput{Role: "merchant", IdentityID: "42", AcceptVersion: "1.0"}, tosCurrentJSON, "contact_name"},
		"reviewer with contact":        {signTosAcceptanceInput{Role: "reviewer", IdentityID: "42", ContactEmail: "a@b.c"}, tosCurrentJSON, "carries no contact"},
		"bad role":                     {signTosAcceptanceInput{Role: "buyer", IdentityID: "42"}, tosCurrentJSON, "role must be"},
		"nothing published":            {merchantTosInput("1.0"), "", "nothing to accept"},
		"backend serves another chain": {merchantTosInput("1.0"), strings.Replace(tosCurrentJSON, `"chain_id":84532`, `"chain_id":8453`, 1), "check REFERRER_API_URL and CHAIN_ID"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := &tosBackend{current: c.current}
			newTosFixture(t, b)
			_, _, err := handleSignTosAcceptance(context.Background(), nil, c.in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
			if b.posts != 0 {
				t.Error("a refused call sent an acceptance")
			}
		})
	}
}

// A 403 means the key is not the owner (a Safe, a transferred identity): the error must say so.
func TestSignTos_NotOwnerAdvice(t *testing.T) {
	b := &tosBackend{current: tosCurrentJSON, postCode: http.StatusForbidden,
		postReply: `{"error":"the signature is not from the identity's current owner","code":"bad_signature"}`}
	newTosFixture(t, b)
	_, _, err := handleSignTosAcceptance(context.Background(), nil, merchantTosInput("1.0"))
	if err == nil || !strings.Contains(err.Error(), "current on-chain owner") {
		t.Fatalf("err = %v", err)
	}
}

// Provider backends: Turnkey and CDP cannot sign the backend request, and Privy's policy v2 does
// not allow TosAcceptance. Each must refuse before signing anything.
func TestSignTos_ProviderBackendsRefuse(t *testing.T) {
	b := &tosBackend{current: tosCurrentJSON}
	newTosFixture(t, b)
	prev := signerKeys
	t.Cleanup(func() { signerKeys = prev })
	for name, key := range map[string]Signer{"privy": &privySigner{}, "turnkey": &turnkeySigner{}, "cdp": &cdpSigner{}} {
		signerKeys = &keystore{keys: map[string]Signer{"42": key}}
		_, _, err := handleSignTosAcceptance(context.Background(), nil, merchantTosInput("1.0"))
		if err == nil || !strings.Contains(err.Error(), "nothing was") {
			t.Errorf("%s: err = %v, want a refusal before signing", name, err)
		}
	}
	if b.posts != 0 {
		t.Error("a provider backend sent an acceptance")
	}
}
