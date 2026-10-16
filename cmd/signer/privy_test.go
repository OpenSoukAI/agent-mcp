package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gowebpki/jcs"
)

// fakePrivy implements the Privy wallet API slice the adapter uses. It checks basic auth, the
// app-id header and the authorization signature over the RFC 8785 canonical payload, so a passing
// test proves the request is one real Privy would accept.
type fakePrivy struct {
	t       *testing.T
	srv     *httptest.Server
	wallet  *ecdsa.PrivateKey
	authPub *ecdsa.PublicKey
	appID   string
	secret  string
	id      string
	noOwner bool
	deny    bool
	alterTo *common.Address

	mu       sync.Mutex
	requests []map[string]any
}

func newFakePrivy(t *testing.T) (*fakePrivy, string) {
	t.Helper()
	wallet, _ := crypto.HexToECDSA(testLocalKeyHex)
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(auth)
	f := &fakePrivy{t: t, wallet: wallet, authPub: &auth.PublicKey, appID: "app-test", secret: "secret-test", id: "wallet123"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f, "wallet-auth:" + base64.StdEncoding.EncodeToString(der)
}

func (f *fakePrivy) env(authKey string) map[string]string {
	return map[string]string{"SIGNER_BACKEND": "privy", "PRIVY_API_BASE_URL": f.srv.URL, "PRIVY_APP_ID": f.appID,
		"PRIVY_APP_SECRET": f.secret, "PRIVY_AUTHORIZATION_KEY": authKey, "AGENT_WALLETS": "*:" + f.id}
}

func (f *fakePrivy) walletAddr() common.Address { return crypto.PubkeyToAddress(f.wallet.PublicKey) }

func (f *fakePrivy) authorised(r *http.Request, body []byte, needSig bool) bool {
	user, pass, ok := r.BasicAuth()
	if !ok || user != f.appID || pass != f.secret || r.Header.Get("privy-app-id") != f.appID {
		return false
	}
	if !needSig {
		return true
	}
	var parsed any
	if json.Unmarshal(body, &parsed) != nil {
		return false
	}
	payload, _ := json.Marshal(map[string]any{"version": 1, "method": r.Method, "url": f.srv.URL + r.URL.Path,
		"body": parsed, "headers": map[string]any{"privy-app-id": f.appID}})
	canon, err := jcs.Transform(payload)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("privy-authorization-signature"))
	if err != nil {
		return false
	}
	h := sha256.Sum256(canon)
	return ecdsa.VerifyASN1(f.authPub, h[:], sig)
}

func (f *fakePrivy) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	walletPath := "/v1/wallets/" + f.id
	switch {
	case r.Method == http.MethodGet && r.URL.Path == walletPath:
		if !f.authorised(r, nil, false) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		owner := any("quorum-owner")
		if f.noOwner {
			owner = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": f.id, "address": f.walletAddr().Hex(), "chain_type": "ethereum", "owner_id": owner})
	case r.Method == http.MethodPost && r.URL.Path == walletPath+"/rpc":
		if !f.authorised(r, body, true) {
			http.Error(w, `{"error":"invalid authorization signature"}`, http.StatusUnauthorized)
			return
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		if f.deny {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "policy_violation", "message": "denied by policy"})
			return
		}
		data := f.rpc(req)
		_ = json.NewEncoder(w).Encode(map[string]any{"method": req["method"], "data": data})
	default:
		if strings.Contains(r.URL.Path, "raw_sign") {
			f.t.Errorf("raw_sign reached Privy: %s", r.URL.Path)
		}
		http.NotFound(w, r)
	}
}

func (f *fakePrivy) rpc(req map[string]any) map[string]any {
	params, _ := req["params"].(map[string]any)
	switch req["method"] {
	case "eth_signTypedData_v4":
		raw, _ := json.Marshal(params["typed_data"])
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		m["primaryType"] = m["primary_type"]
		delete(m, "primary_type")
		raw, _ = json.Marshal(m)
		var td apitypes.TypedData
		if err := json.Unmarshal(raw, &td); err != nil {
			f.t.Errorf("typed_data is not EIP-712 JSON: %v", err)
			return nil
		}
		hash, _, err := apitypes.TypedDataAndHash(td)
		if err != nil {
			f.t.Errorf("hash typed_data: %v", err)
			return nil
		}
		sig, _ := crypto.Sign(hash, f.wallet)
		sig[64] += 27
		return map[string]any{"signature": hexutil.Encode(sig), "encoding": "hex"}
	case "eth_signTransaction":
		tx, chainID := f.txFromParams(params["transaction"].(map[string]any))
		if f.alterTo != nil {
			tx = alterTo(tx, *f.alterTo)
		}
		signed, _ := types.SignTx(tx, types.LatestSignerForChainID(chainID), f.wallet)
		b, _ := signed.MarshalBinary()
		return map[string]any{"signed_transaction": hexutil.Encode(b), "encoding": "rlp"}
	case "personal_sign":
		if params["encoding"] != "hex" {
			f.t.Errorf("personal_sign encoding %v, want hex", params["encoding"])
		}
		msg, _ := hexutil.Decode(params["message"].(string))
		sig, _ := crypto.Sign(accounts.TextHash(msg), f.wallet)
		sig[64] += 27
		return map[string]any{"signature": hexutil.Encode(sig), "encoding": "hex"}
	default:
		f.t.Errorf("unexpected Privy RPC method %v", req["method"])
		return nil
	}
}

func (f *fakePrivy) txFromParams(p map[string]any) (*types.Transaction, *big.Int) {
	num := func(k string) *big.Int {
		s, _ := p[k].(string)
		n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
		if !ok {
			f.t.Errorf("transaction field %s = %v is not a 0x hex quantity", k, p[k])
			return new(big.Int)
		}
		return n
	}
	to := common.HexToAddress(p["to"].(string))
	data, _ := hexutil.Decode(p["data"].(string))
	chainID := num("chain_id")
	if p["type"] == float64(2) {
		return types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: num("nonce").Uint64(), GasTipCap: num("max_priority_fee_per_gas"),
			GasFeeCap: num("max_fee_per_gas"), Gas: num("gas_limit").Uint64(), To: &to, Value: num("value"), Data: data}), chainID
	}
	return types.NewTx(&types.LegacyTx{Nonce: num("nonce").Uint64(), GasPrice: num("gas_price"), Gas: num("gas_limit").Uint64(),
		To: &to, Value: num("value"), Data: data}), chainID
}

func fakePrivyKeystore(t *testing.T, f *fakePrivy, authKey string) *keystore {
	t.Helper()
	ks, report, err := loadKeystore(context.Background(), envOf(f.env(authKey)), nil)
	if err != nil {
		t.Fatalf("load privy keystore: %v", err)
	}
	if len(report) != 1 || !strings.Contains(report[0], f.walletAddr().Hex()) || !strings.Contains(report[0], f.id) {
		t.Fatalf("boot report %v must name the wallet id and address", report)
	}
	return ks
}

func TestPrivy_SignTypedData(t *testing.T) {
	for _, c := range commitmentToolCases() {
		t.Run(c.primary, func(t *testing.T) {
			pinEnv(t)
			f, auth := newFakePrivy(t)
			signerKeys = fakePrivyKeystore(t, f, auth)
			if err := c.call(); err != nil {
				t.Fatalf("tool refused: %v", err)
			}
			if len(f.requests) != 1 {
				t.Fatalf("%d RPC requests, want 1", len(f.requests))
			}
			td := f.requests[0]["params"].(map[string]any)["typed_data"].(map[string]any)
			typesMap, _ := td["types"].(map[string]any)
			if td["primary_type"] != c.primary || td["message"] == nil || typesMap["EIP712Domain"] == nil {
				t.Fatalf("typed_data %v must carry primary_type %s, the message and EIP712Domain", td, c.primary)
			}
		})
	}
}

func TestPrivy_SignTx(t *testing.T) {
	chainID := big.NewInt(84532)
	for _, tx := range sampleTxs(chainID) {
		f, auth := newFakePrivy(t)
		ks := fakePrivyKeystore(t, f, auth)
		opts := transactOpts(context.Background(), ks.fallback, chainID)
		signed, err := opts.Signer(opts.From, tx)
		if err != nil {
			t.Fatalf("type %d: %v", tx.Type(), err)
		}
		signer := types.LatestSignerForChainID(chainID)
		if from, _ := types.Sender(signer, signed); from != f.walletAddr() || signer.Hash(signed) != signer.Hash(tx) {
			t.Fatalf("type %d: wrong sender or fields", tx.Type())
		}
		p := f.requests[0]["params"].(map[string]any)["transaction"].(map[string]any)
		if p["chain_id"] == nil || p["to"] == nil {
			t.Fatalf("transaction params %v must carry chain_id and to", p)
		}
		evil := common.HexToAddress("0x00000000000000000000000000000000000000ee")
		f.alterTo = &evil
		if _, err := opts.Signer(opts.From, tx); err == nil {
			t.Fatalf("type %d: a signed tx with altered fields must be refused", tx.Type())
		}
	}
}

func TestPrivy_PersonalSignForAgentAuth(t *testing.T) {
	f, auth := newFakePrivy(t)
	ks := fakePrivyKeystore(t, f, auth)
	body, ts := []byte(`{"merchant_id":"4"}`), int64(1792000000)
	sigHex, err := agentAuthSignature(context.Background(), body, ts, ks.fallback)
	if err != nil {
		t.Fatal(err)
	}
	p := f.requests[0]["params"].(map[string]any)
	if f.requests[0]["method"] != "personal_sign" || p["message"] != hexutil.Encode(agentAuthPayloadHash(body, ts)) {
		t.Fatalf("agent auth sent %v, want personal_sign of the 32-byte payload hash", f.requests[0])
	}
	if got, err := recoverAgentAuth(body, ts, sigHex); err != nil || !strings.EqualFold(got, f.walletAddr().Hex()) {
		t.Fatalf("agent auth recovers to %s (%v)", got, err)
	}
}

func TestPrivy_RefusesDigestAndSurfacesPolicyViolation(t *testing.T) {
	f, auth := newFakePrivy(t)
	ks := fakePrivyKeystore(t, f, auth)
	if _, err := ks.fallback.SignDigest(context.Background(), [32]byte{1}); err != errRawDigestRefused {
		t.Fatalf("SignDigest: want errRawDigestRefused, got %v", err)
	}
	if len(f.requests) != 0 {
		t.Fatal("a refused digest reached Privy")
	}
	f.deny = true
	td, _ := intentAccessTypedData(fixedIntentAccessPayload())
	_, err := ks.fallback.SignTypedData(context.Background(), td)
	if err == nil || !strings.Contains(err.Error(), "policy_violation") || !strings.Contains(err.Error(), "eth_signTypedData_v4") {
		t.Fatalf("want the provider's policy_violation naming the method, got %v", err)
	}
}

func TestPrivy_BootChecks(t *testing.T) {
	f, auth := newFakePrivy(t)
	f.noOwner = true
	if _, _, err := loadKeystore(context.Background(), envOf(f.env(auth)), nil); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("a wallet with no owner must be refused, got %v", err)
	}
	f.noOwner = false
	for _, c := range []struct{ name, key, val, want string }{
		{"no authorization key", "PRIVY_AUTHORIZATION_KEY", "", "PRIVY_AUTHORIZATION_KEY"},
		{"key without prefix", "PRIVY_AUTHORIZATION_KEY", strings.TrimPrefix(auth, "wallet-auth:"), "wallet-auth:"},
		{"no app secret", "PRIVY_APP_SECRET", "", "PRIVY_APP_SECRET"},
		{"wrong app secret", "PRIVY_APP_SECRET", "nope", "401"},
		{"wallet id with a slash", "AGENT_WALLETS", "*:../policies", "wallet id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := f.env(auth)
			if c.val == "" {
				delete(env, c.key)
			} else {
				env[c.key] = c.val
			}
			_, _, err := loadKeystore(context.Background(), envOf(env), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error naming %q, got %v", c.want, err)
			}
			if strings.Contains(err.Error(), f.secret) || strings.Contains(err.Error(), strings.TrimPrefix(auth, "wallet-auth:")) {
				t.Fatal("an error printed a credential")
			}
		})
	}
}

func TestPrivyAuthSignatureIsOverCanonicalJSON(t *testing.T) {
	_, auth := newFakePrivy(t)
	cred, err := privyCredential(auth)
	if err != nil {
		t.Fatal(err)
	}
	// Keys out of order and characters Go's encoder escapes but RFC 8785 does not.
	body := []byte(`{"params":{"message":"a<b&c` + " " + `"},"method":"personal_sign"}`)
	url := "https://api.privy.io/v1/wallets/w1/rpc"
	sigB64, canon, err := cred.privySignature("POST", url, body, "app-x")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"body":{"method":"personal_sign","params":{"message":"a<b&c` + " " + `"}},"headers":{"privy-app-id":"app-x"},"method":"POST","url":"https://api.privy.io/v1/wallets/w1/rpc","version":1}`
	if string(canon) != want {
		t.Fatalf("canonical payload\n got %s\nwant %s", canon, want)
	}
	sig, _ := base64.StdEncoding.DecodeString(sigB64)
	h := sha256.Sum256(canon)
	if !ecdsa.VerifyASN1(&cred.priv.PublicKey, h[:], sig) {
		t.Fatal("signature does not verify over the canonical payload")
	}
}
