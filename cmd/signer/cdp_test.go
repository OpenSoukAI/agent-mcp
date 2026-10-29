package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// fakeCDP implements the slice of the CDP API the adapter uses. It verifies the bearer JWT against
// the test API key, the wallet JWT (on every /accounts write) against the test wallet credential —
// including reqHash == sha256(the exact request body) — and signs with a local secp256k1 key, so a
// passing test proves the JWTs, the body encoding and the signature handling end to end.
type fakeCDP struct {
	t          *testing.T
	srv        *httptest.Server
	apiPub     ed25519.PublicKey
	walletPub  *ecdsa.PublicKey
	evmKey     *ecdsa.PrivateKey // the account CDP signs as
	foreignKey *ecdsa.PrivateKey // set to make the fake sign with a different key than evmKey
	status     int               // forced non-200 status
	errBody    string
	delay      time.Duration // artificial latency, bounded by the request's own context

	mu   sync.Mutex
	hits int
}

func newFakeCDP(t *testing.T) (*fakeCDP, *cdpClient) {
	t.Helper()
	apiPub, apiPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	walletCred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evmKey, err := crypto.HexToECDSA(testLocalKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCDP{t: t, apiPub: apiPub, walletPub: &walletCred.PublicKey, evmKey: evmKey}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := &cdpClient{
		base: f.srv.URL,
		host: u.Host,
		key:  &cdpAPIKey{id: "organizations/org/apiKeys/key-1", priv: apiPriv},
		wallet: &p256Credential{priv: walletCred, pubHex: hex.EncodeToString(
			elliptic.MarshalCompressed(elliptic.P256(), walletCred.X, walletCred.Y))},
		http: &http.Client{},
	}
	return f, c
}

func (f *fakeCDP) addr() common.Address { return crypto.PubkeyToAddress(f.evmKey.PublicKey) }

func (f *fakeCDP) signKey() *ecdsa.PrivateKey {
	if f.foreignKey != nil {
		return f.foreignKey
	}
	return f.evmKey
}

func (f *fakeCDP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-r.Context().Done():
			return
		}
	}

	uri := r.Method + " " + r.Host + r.URL.Path
	if !f.verifyBearer(r, uri) {
		http.Error(w, `{"errorType":"unauthorized","errorMessage":"bad bearer"}`, http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		if strings.Contains(r.URL.Path, "/accounts") && !f.verifyWalletJWT(r, uri, body) {
			http.Error(w, `{"errorType":"unauthorized","errorMessage":"bad wallet jwt"}`, http.StatusUnauthorized)
			return
		}
	}

	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.errBody))
		return
	}

	switch {
	case strings.HasSuffix(r.URL.Path, "/sign/typed-data"):
		f.signTypedData(w, body)
	case strings.HasSuffix(r.URL.Path, "/sign/transaction"):
		f.signTransaction(w, body)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCDP) verifyBearer(r *http.Request, uri string) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	var header struct {
		Alg   string `json:"alg"`
		Kid   string `json:"kid"`
		Nonce string `json:"nonce"`
	}
	var claims struct {
		Sub  string   `json:"sub"`
		Iss  string   `json:"iss"`
		Aud  []string `json:"aud"`
		Nbf  int64    `json:"nbf"`
		Exp  int64    `json:"exp"`
		URIs []string `json:"uris"`
	}
	decodeJWTPart(f.t, parts[0], &header)
	decodeJWTPart(f.t, parts[1], &claims)
	if header.Alg != "EdDSA" || header.Kid == "" || len(header.Nonce) != 32 {
		return false
	}
	if claims.Iss != "cdp" || len(claims.Aud) != 1 || claims.Aud[0] != "cdp_service" || claims.Sub != header.Kid {
		return false
	}
	if len(claims.URIs) != 1 || claims.URIs[0] != uri {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return ed25519.Verify(f.apiPub, []byte(parts[0]+"."+parts[1]), sig)
}

func (f *fakeCDP) verifyWalletJWT(r *http.Request, uri string, body []byte) bool {
	tok := r.Header.Get("X-Wallet-Auth")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	var claims struct {
		URIs    []string `json:"uris"`
		ReqHash string   `json:"reqHash"`
	}
	decodeJWTPart(f.t, parts[0], &header)
	decodeJWTPart(f.t, parts[1], &claims)
	if header.Alg != "ES256" {
		return false
	}
	if len(claims.URIs) != 1 || claims.URIs[0] != uri {
		return false
	}
	want := sha256.Sum256(body)
	if claims.ReqHash != hex.EncodeToString(want[:]) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rr := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(f.walletPub, h[:], rr, ss)
}

func (f *fakeCDP) signTypedData(w http.ResponseWriter, body []byte) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		f.t.Errorf("sign/typed-data body is not JSON: %v", err)
		http.Error(w, `{"errorType":"bad_request","errorMessage":"not json"}`, http.StatusBadRequest)
		return
	}
	for _, k := range []string{"domain", "types", "primaryType", "message"} {
		if _, ok := raw[k]; !ok {
			f.t.Errorf("sign/typed-data body %s missing key %q", body, k)
		}
	}
	var td apitypes.TypedData
	if err := json.Unmarshal(body, &td); err != nil {
		f.t.Errorf("sign/typed-data body is not EIP-712 typed data: %v", err)
		http.Error(w, `{"errorType":"bad_request","errorMessage":"not typed data"}`, http.StatusBadRequest)
		return
	}
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		f.t.Errorf("hash typed data: %v", err)
		http.Error(w, `{"errorType":"bad_request","errorMessage":"bad typed data"}`, http.StatusBadRequest)
		return
	}
	sig, err := crypto.Sign(hash, f.signKey())
	if err != nil {
		f.t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"signature": hexutil.Encode(sig)})
}

func (f *fakeCDP) signTransaction(w http.ResponseWriter, body []byte) {
	var req struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		f.t.Errorf("sign/transaction body is not JSON: %v", err)
		http.Error(w, `{"errorType":"bad_request","errorMessage":"not json"}`, http.StatusBadRequest)
		return
	}
	raw, err := hexutil.Decode(req.Transaction)
	if err != nil {
		f.t.Errorf("sign/transaction body.transaction is not 0x-hex: %v", err)
		http.Error(w, `{"errorType":"bad_request","errorMessage":"bad transaction"}`, http.StatusBadRequest)
		return
	}
	tx, chainID := decodeUnsignedForTest(f.t, raw)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), f.signKey())
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := signed.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"signedTransaction": hexutil.Encode(b)})
}

func reviewTDFixture(addr common.Address) apitypes.TypedData {
	_ = addr
	td, err := reviewTypedData(reviewCommitmentPayload{
		Domain:  commitmentDomain{Name: "ReferrerReviews", Version: "1", ChainID: 84532, VerifyingContract: "0x000000000000000000000000000000000000aBcD"},
		Message: commitmentMessage{AgentID: "7", MerchantID: "4", ProductID: b32a, ContentHash: b32b, Nonce: "1", Expiry: "1893456000"},
	})
	if err != nil {
		panic(err)
	}
	return td
}

func TestCDPSignTypedDataRecovers(t *testing.T) {
	f, c := newFakeCDP(t)
	s := &cdpSigner{c: c, addr: f.addr()}
	td := reviewTDFixture(s.addr)

	sig, err := s.SignTypedData(context.Background(), td)
	if err != nil {
		t.Fatalf("SignTypedData: %v", err)
	}
	hash, _, _ := apitypes.TypedDataAndHash(td)
	pub, err := crypto.SigToPub(hash, sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != s.Address() {
		t.Fatalf("signature does not recover to %s: %v", s.Address().Hex(), err)
	}
}

func TestCDPSignTxRecovers(t *testing.T) {
	f, c := newFakeCDP(t)
	s := &cdpSigner{c: c, addr: f.addr()}
	chainID := big.NewInt(84532)
	tx := sampleTxs(chainID)[0] // DynamicFeeTx
	opts := transactOpts(context.Background(), s, chainID)

	signed, err := opts.Signer(opts.From, tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, signed)
	if err != nil || from != s.Address() {
		t.Fatalf("recovered sender %s, want %s (%v)", from.Hex(), s.Address().Hex(), err)
	}
}

func TestCDPRefusesLegacyTxBeforeSending(t *testing.T) {
	f, c := newFakeCDP(t)
	s := &cdpSigner{c: c, addr: f.addr()}
	chainID := big.NewInt(84532)
	tx := sampleTxs(chainID)[1] // LegacyTx

	if _, err := s.SignTx(context.Background(), tx, chainID); err == nil {
		t.Fatal("a legacy transaction must be refused")
	}
	if f.hits != 0 {
		t.Fatalf("the fake was hit %d times; a refused legacy tx must not reach CDP", f.hits)
	}
}

func TestCDPRefusesForeignSignature(t *testing.T) {
	f, c := newFakeCDP(t)
	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.foreignKey = other
	s := &cdpSigner{c: c, addr: f.addr()}

	td := reviewTDFixture(s.addr)
	if _, err := s.SignTypedData(context.Background(), td); err == nil {
		t.Fatal("a typed-data signature from a different key must be refused")
	}

	chainID := big.NewInt(84532)
	tx := sampleTxs(chainID)[0]
	if _, err := s.SignTx(context.Background(), tx, chainID); err == nil {
		t.Fatal("a transaction signature from a different key must be refused")
	}
}

func TestCDPRefusesDigestAndPersonalSign(t *testing.T) {
	f, c := newFakeCDP(t)
	s := &cdpSigner{c: c, addr: f.addr()}

	if _, err := s.SignDigest(context.Background(), [32]byte{1}); !errors.Is(err, errRawDigestRefused) {
		t.Fatalf("SignDigest: want errRawDigestRefused, got %v", err)
	}
	if _, err := s.SignPersonalMessage(context.Background(), []byte("hi")); err == nil || !strings.Contains(err.Error(), "cannot personal-sign") {
		t.Fatalf("SignPersonalMessage: want an error mentioning cannot personal-sign, got %v", err)
	}
	if _, err := agentAuthSignature(context.Background(), []byte("{}"), 1792000000, s); err == nil {
		t.Fatal("agentAuthSignature must fail under SIGNER_BACKEND=cdp")
	}
}

func TestCDPPolicyViolationSurfaces(t *testing.T) {
	f, c := newFakeCDP(t)
	f.status = http.StatusForbidden
	f.errBody = `{"errorType":"policy_violation","errorMessage":"x"}`
	s := &cdpSigner{c: c, addr: f.addr()}

	td := reviewTDFixture(s.addr)
	_, err := s.SignTypedData(context.Background(), td)
	if err == nil || !strings.Contains(err.Error(), "policy_violation") {
		t.Fatalf("want an error naming policy_violation, got %v", err)
	}
}

func TestCDPBoundsEachCall(t *testing.T) {
	prev := providerCallTimeout
	providerCallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { providerCallTimeout = prev })

	f, c := newFakeCDP(t)
	f.delay = 2 * time.Second
	s := &cdpSigner{c: c, addr: f.addr()}
	td := reviewTDFixture(s.addr)

	done := make(chan error, 1)
	go func() {
		_, err := s.SignTypedData(context.Background(), td)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled CDP response must not return success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SignTypedData on a stalled CDP did not return: no per-call deadline")
	}
}

func TestCDPBodyWithHTMLCharsHashes(t *testing.T) {
	f, c := newFakeCDP(t)
	s := &cdpSigner{c: c, addr: f.addr()}

	p := intentSkipCommitmentPayload{
		Domain: commitmentDomain{Name: "ReferrerIntentAccess", Version: "1", ChainID: 84532, VerifyingContract: "0x000000000000000000000000000000000000aBcD"},
		Message: intentSkipCommitmentMessage{
			AgentID: "7", IntentID: "intent-1", Reason: "a<b&c>",
			Nonce: "0x" + strings.Repeat("ab", 32), Expiry: "1893456000",
		},
	}
	td, err := intentSkipTypedData(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignTypedData(context.Background(), td); err != nil {
		t.Fatalf("SignTypedData with HTML characters in the reason: %v", err)
	}
}
