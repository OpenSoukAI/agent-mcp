package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// fakeTurnkey implements the slice of the Turnkey API the adapter uses. It verifies every
// X-Stamp against the configured API public key and signs with a secp256k1 wallet key, so a
// passing test proves the stamp, the payload encoding and the signature handling end to end.
type fakeTurnkey struct {
	t       *testing.T
	srv     *httptest.Server
	wallet  *ecdsa.PrivateKey
	signer  *ecdsa.PrivateKey // signs instead of wallet when set (a wrong signWith)
	apiPub  string
	org     string
	highS   bool
	status  string // forced terminal status for submissions, e.g. FAILED
	pending int    // polls answered PENDING before COMPLETED
	stuck   bool   // CONSENSUS_NEEDED forever
	alterTo *common.Address

	mu       sync.Mutex
	requests []map[string]any
	polls    map[string]int
	results  map[string]map[string]any
}

func newFakeTurnkey(t *testing.T) (*fakeTurnkey, string) {
	t.Helper()
	wallet, _ := crypto.HexToECDSA(testLocalKeyHex)
	api, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeTurnkey{t: t, wallet: wallet, apiPub: hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), api.X, api.Y)),
		org: "org-test", polls: map[string]int{}, results: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f, hex.EncodeToString(api.D.FillBytes(make([]byte, 32)))
}

func (f *fakeTurnkey) env(t *testing.T, privHex string) {
	t.Setenv("TURNKEY_API_BASE_URL", f.srv.URL)
	t.Setenv("TURNKEY_ORG_ID", f.org)
	t.Setenv("TURNKEY_API_PUBLIC_KEY", f.apiPub)
	t.Setenv("TURNKEY_API_PRIVATE_KEY", privHex)
}

func (f *fakeTurnkey) walletAddr() common.Address { return crypto.PubkeyToAddress(f.wallet.PublicKey) }

func (f *fakeTurnkey) verifyStamp(r *http.Request, body []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Stamp"))
	if err != nil {
		return false
	}
	var st struct{ PublicKey, Signature, Scheme string }
	if json.Unmarshal(raw, &st) != nil || st.Scheme != "SIGNATURE_SCHEME_TK_API_P256" || st.PublicKey != f.apiPub {
		return false
	}
	pubBytes, _ := hex.DecodeString(st.PublicKey)
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
	sig, err := hex.DecodeString(st.Signature)
	if x == nil || err != nil {
		return false
	}
	h := sha256.Sum256(body)
	return ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig)
}

func (f *fakeTurnkey) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !f.verifyStamp(r, body) {
		http.Error(w, `{"message":"invalid stamp"}`, http.StatusUnauthorized)
		return
	}
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	if req["organizationId"] != f.org {
		http.Error(w, `{"message":"wrong organization"}`, http.StatusBadRequest)
		return
	}
	// Live Turnkey matches signWith case-sensitively against the checksummed address (404 "Could not
	// find any resource to sign with. Addresses are case sensitive." on 2026-10-16).
	if p, ok := req["parameters"].(map[string]any); ok && p["signWith"] != f.walletAddr().Hex() {
		http.Error(w, `{"message":"Could not find any resource to sign with. Addresses are case sensitive."}`, http.StatusNotFound)
		return
	}
	switch r.URL.Path {
	case "/public/v1/query/whoami":
		_ = json.NewEncoder(w).Encode(map[string]any{"organizationId": f.org, "userId": "user-signer", "username": "referrer-signer"})
	case "/public/v1/submit/sign_raw_payload":
		f.activity(w, "sign-raw", f.signRaw(req))
	case "/public/v1/submit/sign_transaction":
		f.activity(w, "sign-tx", f.signTx(req))
	case "/public/v1/query/get_activity":
		f.mu.Lock()
		id, _ := req["activityId"].(string)
		f.polls[id]++
		n := f.polls[id]
		res := f.results[id]
		f.mu.Unlock()
		status := "ACTIVITY_STATUS_COMPLETED"
		if f.stuck {
			status = "ACTIVITY_STATUS_CONSENSUS_NEEDED"
		} else if n <= f.pending {
			status = "ACTIVITY_STATUS_PENDING"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{"id": id, "status": status, "result": res}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeTurnkey) activity(w http.ResponseWriter, id string, result map[string]any) {
	f.mu.Lock()
	f.results[id] = result
	f.mu.Unlock()
	status := "ACTIVITY_STATUS_COMPLETED"
	switch {
	case f.status != "":
		_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{"id": id, "status": f.status,
			"failure": map[string]any{"message": "policy denied the activity"}}})
		return
	case f.stuck:
		status = "ACTIVITY_STATUS_CONSENSUS_NEEDED"
	case f.pending > 0:
		status = "ACTIVITY_STATUS_PENDING"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{"id": id, "status": status, "result": result}})
}

func (f *fakeTurnkey) key() *ecdsa.PrivateKey {
	if f.signer != nil {
		return f.signer
	}
	return f.wallet
}

func (f *fakeTurnkey) signRaw(req map[string]any) map[string]any {
	p, _ := req["parameters"].(map[string]any)
	if req["type"] != "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2" || p["encoding"] != "PAYLOAD_ENCODING_EIP712" || p["hashFunction"] != "HASH_FUNCTION_NO_OP" {
		f.t.Errorf("raw payload request is not EIP-712 typed data: %v", req)
		return nil
	}
	var td apitypes.TypedData
	if err := json.Unmarshal([]byte(p["payload"].(string)), &td); err != nil {
		f.t.Errorf("payload is not typed-data JSON: %v", err)
		return nil
	}
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		f.t.Errorf("hash payload: %v", err)
		return nil
	}
	sig, _ := crypto.Sign(hash, f.key())
	s := new(big.Int).SetBytes(sig[32:64])
	if f.highS {
		s = new(big.Int).Sub(secp256k1N, s)
		sig[64] ^= 1
	}
	return map[string]any{"signRawPayloadResult": map[string]any{
		"r": hex.EncodeToString(sig[:32]), "s": hex.EncodeToString(s.FillBytes(make([]byte, 32))), "v": hex.EncodeToString(sig[64:])}}
}

func (f *fakeTurnkey) signTx(req map[string]any) map[string]any {
	p, _ := req["parameters"].(map[string]any)
	raw, err := hex.DecodeString(p["unsignedTransaction"].(string))
	if err != nil || p["type"] != "TRANSACTION_TYPE_ETHEREUM" {
		f.t.Errorf("bad sign_transaction parameters: %v", p)
		return nil
	}
	tx, chainID := decodeUnsignedForTest(f.t, raw)
	if f.alterTo != nil {
		tx = alterTo(tx, *f.alterTo)
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), f.key())
	if err != nil {
		f.t.Errorf("sign: %v", err)
		return nil
	}
	b, _ := signed.MarshalBinary()
	return map[string]any{"signTransactionResult": map[string]any{"signedTransaction": hex.EncodeToString(b)}}
}

// decodeUnsignedForTest parses the unsigned encodings unsignedTxRLP produces, returning the
// chain id they commit to (an unsigned legacy tx carries it only in the EIP-155 fields).
func decodeUnsignedForTest(t *testing.T, raw []byte) (*types.Transaction, *big.Int) {
	t.Helper()
	if len(raw) > 0 && raw[0] == types.DynamicFeeTxType {
		var f struct {
			ChainID              *big.Int
			Nonce                uint64
			GasTipCap, GasFeeCap *big.Int
			Gas                  uint64
			To                   *common.Address `rlp:"nil"`
			Value                *big.Int
			Data                 []byte
			AccessList           types.AccessList
		}
		if err := rlp.DecodeBytes(raw[1:], &f); err != nil {
			t.Fatalf("decode unsigned 1559 tx: %v", err)
		}
		return types.NewTx(&types.DynamicFeeTx{ChainID: f.ChainID, Nonce: f.Nonce, GasTipCap: f.GasTipCap, GasFeeCap: f.GasFeeCap,
			Gas: f.Gas, To: f.To, Value: f.Value, Data: f.Data, AccessList: f.AccessList}), f.ChainID
	}
	var f struct {
		Nonce    uint64
		GasPrice *big.Int
		Gas      uint64
		To       *common.Address `rlp:"nil"`
		Value    *big.Int
		Data     []byte
		ChainID  *big.Int
		Z1, Z2   uint
	}
	if err := rlp.DecodeBytes(raw, &f); err != nil {
		t.Fatalf("decode unsigned legacy tx: %v", err)
	}
	return types.NewTx(&types.LegacyTx{Nonce: f.Nonce, GasPrice: f.GasPrice, Gas: f.Gas, To: f.To, Value: f.Value, Data: f.Data}), f.ChainID
}

func alterTo(tx *types.Transaction, to common.Address) *types.Transaction {
	if tx.Type() == types.DynamicFeeTxType {
		return types.NewTx(&types.DynamicFeeTx{ChainID: tx.ChainId(), Nonce: tx.Nonce(), GasTipCap: tx.GasTipCap(), GasFeeCap: tx.GasFeeCap(),
			Gas: tx.Gas(), To: &to, Value: tx.Value(), Data: tx.Data()})
	}
	return types.NewTx(&types.LegacyTx{Nonce: tx.Nonce(), GasPrice: tx.GasPrice(), Gas: tx.Gas(), To: &to, Value: tx.Value(), Data: tx.Data()})
}

func fakeTurnkeyKeystore(t *testing.T, f *fakeTurnkey, privHex string) *keystore {
	t.Helper()
	f.env(t, privHex)
	t.Setenv("SIGNER_BACKEND", "turnkey")
	t.Setenv("AGENT_WALLETS", "*:"+f.walletAddr().Hex())
	ks, report, err := loadKeystore(context.Background(), os.Getenv, nil)
	if err != nil {
		t.Fatalf("load turnkey keystore: %v", err)
	}
	if len(report) != 2 || !strings.Contains(report[0], f.walletAddr().Hex()) || !strings.Contains(report[1], "user-signer") {
		t.Fatalf("boot report %v must name the wallet address and the API user the policy is scoped to", report)
	}
	return ks
}

func sampleTxs(chainID *big.Int) []*types.Transaction {
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	return []*types.Transaction{
		types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 7, GasTipCap: big.NewInt(3), GasFeeCap: big.NewInt(40), Gas: 90000, To: &to, Value: big.NewInt(5), Data: []byte{0xde, 0xad}}),
		types.NewTx(&types.LegacyTx{Nonce: 8, GasPrice: big.NewInt(9), Gas: 21000, To: &to, Value: big.NewInt(1)}),
	}
}

func TestUnsignedTxRLPIsTheSignerPreimage(t *testing.T) {
	chainID := big.NewInt(84532)
	signer := types.LatestSignerForChainID(chainID)
	for _, tx := range sampleTxs(chainID) {
		raw, err := unsignedTxRLP(tx, chainID)
		if err != nil {
			t.Fatal(err)
		}
		if got := crypto.Keccak256Hash(raw); got != signer.Hash(tx) {
			t.Fatalf("type %d: keccak(unsigned) %s != signer hash %s", tx.Type(), got.Hex(), signer.Hash(tx).Hex())
		}
	}
}

func TestProviderTypedDataJSON(t *testing.T) {
	td, err := erc3009ReceiveTypedData(vectorAuth(), big.NewInt(84532), "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "2")
	if err != nil {
		t.Fatal(err)
	}
	m, err := providerTypedDataJSON(td, "primaryType", false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	s := string(b)
	for _, want := range []string{`"primaryType":"ReceiveWithAuthorization"`, `"chainId":84532`,
		`"verifyingContract":"0x036cbd53842c5426634e7929541ec2318f3dcf7e"`, `"EIP712Domain"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	// Every hex value must be lowercase: Turnkey evaluates policies on lowercase hex.
	for _, tok := range strings.Split(s, `"`) {
		if strings.HasPrefix(tok, "0x") && tok != strings.ToLower(tok) {
			t.Fatalf("hex value %s is not lowercase", tok)
		}
	}
	// The provider hashes this JSON; it must be the same EIP-712 message.
	var back apitypes.TypedData
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	h1, _, _ := apitypes.TypedDataAndHash(td)
	h2, _, err := apitypes.TypedDataAndHash(back)
	if err != nil || hex.EncodeToString(h1) != hex.EncodeToString(h2) {
		t.Fatalf("provider JSON hashes to %x (%v), want %x", h2, err, h1)
	}
	if m2, _ := providerTypedDataJSON(td, "primary_type", false); m2["primary_type"] != "ReceiveWithAuthorization" {
		t.Fatal("primary key name must be configurable for Privy")
	}
}

func TestTurnkey_SignTypedDataSendsStructure(t *testing.T) {
	for _, c := range commitmentToolCases() {
		t.Run(c.primary, func(t *testing.T) {
			pinEnv(t)
			f, priv := newFakeTurnkey(t)
			signerKeys = fakeTurnkeyKeystore(t, f, priv)
			if err := c.call(); err != nil {
				t.Fatalf("tool refused: %v", err)
			}
			var sent string
			for _, r := range f.requests {
				if p, ok := r["parameters"].(map[string]any); ok {
					sent, _ = p["payload"].(string)
				}
			}
			if !strings.Contains(sent, `"primaryType":"`+c.primary+`"`) || !strings.Contains(sent, `"message":`) {
				t.Fatalf("payload sent %q must carry the primaryType and message", sent)
			}
		})
	}
}

func TestTurnkey_SignTx(t *testing.T) {
	chainID := big.NewInt(84532)
	for _, tx := range sampleTxs(chainID) {
		f, priv := newFakeTurnkey(t)
		ks := fakeTurnkeyKeystore(t, f, priv)
		opts := transactOpts(context.Background(), ks.fallback, chainID)
		signed, err := opts.Signer(opts.From, tx)
		if err != nil {
			t.Fatalf("type %d: %v", tx.Type(), err)
		}
		signer := types.LatestSignerForChainID(chainID)
		if from, _ := types.Sender(signer, signed); from != f.walletAddr() || signer.Hash(signed) != signer.Hash(tx) {
			t.Fatalf("type %d: sender %s, or the signed fields differ from the request", tx.Type(), from.Hex())
		}
		evil := common.HexToAddress("0x00000000000000000000000000000000000000ee")
		f.alterTo = &evil
		if _, err := opts.Signer(opts.From, tx); err == nil {
			t.Fatalf("type %d: a signed tx whose fields differ from the request must be refused", tx.Type())
		}
	}
}

func TestTurnkey_NormalisesAndRejects(t *testing.T) {
	td, _ := intentAccessTypedData(fixedIntentAccessPayload())
	hash, _, _ := apitypes.TypedDataAndHash(td)

	f, priv := newFakeTurnkey(t)
	ks := fakeTurnkeyKeystore(t, f, priv)
	f.highS = true
	sig, err := ks.fallback.SignTypedData(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	if sig[64] > 1 || new(big.Int).SetBytes(sig[32:64]).Cmp(secp256k1HalfN) > 0 {
		t.Fatal("high-s signature not normalised")
	}
	if pub, _ := crypto.SigToPub(hash, sig); crypto.PubkeyToAddress(*pub) != f.walletAddr() {
		t.Fatal("normalised signature does not recover")
	}
	f.highS = false
	f.signer, _ = crypto.GenerateKey()
	if _, err := ks.fallback.SignTypedData(context.Background(), td); err == nil || !strings.Contains(err.Error(), f.walletAddr().Hex()) {
		t.Fatalf("another key's signature must be refused naming the wallet, got %v", err)
	}
}

func TestTurnkey_Polls(t *testing.T) {
	prevPoll, prevTimeout := turnkeyPollInterval, providerCallTimeout
	turnkeyPollInterval, providerCallTimeout = 5*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { turnkeyPollInterval, providerCallTimeout = prevPoll, prevTimeout })
	td, _ := intentAccessTypedData(fixedIntentAccessPayload())

	f, priv := newFakeTurnkey(t)
	ks := fakeTurnkeyKeystore(t, f, priv)
	f.pending = 2
	if _, err := ks.fallback.SignTypedData(context.Background(), td); err != nil {
		t.Fatalf("pending then completed: %v", err)
	}
	f.pending, f.status = 0, "ACTIVITY_STATUS_FAILED"
	if _, err := ks.fallback.SignTypedData(context.Background(), td); err == nil || !strings.Contains(err.Error(), "policy denied the activity") {
		t.Fatalf("a failed activity must surface the provider's reason, got %v", err)
	}
	f.status, f.stuck = "", true
	start := time.Now()
	_, err := ks.fallback.SignTypedData(context.Background(), td)
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("an activity waiting on consensus must say it needs approval, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("polling ignored the deadline: %v", time.Since(start))
	}
}

func TestTurnkey_RefusesDigestAndPersonal(t *testing.T) {
	f, priv := newFakeTurnkey(t)
	ks := fakeTurnkeyKeystore(t, f, priv)
	before := len(f.requests)
	if _, err := ks.fallback.SignDigest(context.Background(), [32]byte{1}); err != errRawDigestRefused {
		t.Fatalf("SignDigest: want errRawDigestRefused, got %v", err)
	}
	if _, err := agentAuthSignature(context.Background(), []byte("{}"), 1792000000, ks.fallback); err == nil || !strings.Contains(err.Error(), "turnkey") {
		t.Fatalf("agent auth under turnkey must refuse naming the backend, got %v", err)
	}
	if len(f.requests) != before {
		t.Fatalf("a refused signature reached Turnkey (%d requests)", len(f.requests)-before)
	}
}

func TestLoadKeystore_Turnkey(t *testing.T) {
	f, priv := newFakeTurnkey(t)
	f.env(t, priv)
	base := map[string]string{"SIGNER_BACKEND": "turnkey", "TURNKEY_API_BASE_URL": f.srv.URL, "TURNKEY_ORG_ID": f.org,
		"TURNKEY_API_PUBLIC_KEY": f.apiPub, "TURNKEY_API_PRIVATE_KEY": priv, "AGENT_WALLETS": "7:" + f.walletAddr().Hex()}
	ks, _, err := loadKeystore(context.Background(), envOf(base), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := ks.KeyFor("7"); s.Address() != f.walletAddr() {
		t.Fatalf("agent 7 signs as %s", s.Address().Hex())
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no private key", with("TURNKEY_API_PRIVATE_KEY", ""), "TURNKEY_API_PRIVATE_KEY"},
		{"no org", with("TURNKEY_ORG_ID", ""), "TURNKEY_ORG_ID"},
		{"public key of another key", with("TURNKEY_API_PUBLIC_KEY", hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), other.X, other.Y))), "TURNKEY_API_PUBLIC_KEY"},
		{"wallet not an address", with("AGENT_WALLETS", "7:not-an-address"), "address"},
		{"mixed with AGENT_KEYS", with("AGENT_KEYS", "7:0x"+testLocalKeyHex), "AGENT_KEYS"},
		{"no wallets", with("AGENT_WALLETS", ""), "AGENT_WALLETS"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := loadKeystore(context.Background(), envOf(c.env), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error naming %q, got %v", c.want, err)
			}
			if err != nil && strings.Contains(err.Error(), priv) {
				t.Fatal("an error printed the API private key")
			}
		})
	}
	// A bad stamp (whoami rejected) fails at boot, not on the first signature.
	bad := with("TURNKEY_API_PRIVATE_KEY", hex.EncodeToString(other.D.FillBytes(make([]byte, 32))))
	bad["TURNKEY_API_PUBLIC_KEY"] = hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), other.X, other.Y))
	if _, _, err := loadKeystore(context.Background(), envOf(bad), nil); err == nil || !strings.Contains(err.Error(), "whoami") {
		t.Fatalf("rejected credentials must fail at boot, got %v", err)
	}
}

// Turnkey's policy compares message['value'] <= N; a decimal string there made the
// ReceiveWithAuthorization ALLOW miss (live 2026-10-16), so uints that fit a JSON number exactly
// go as numbers, and larger ones stay strings (the comparison then fails closed).
func TestTurnkeyPayloadUintsAreNumbers(t *testing.T) {
	td, err := erc3009ReceiveTypedData(vectorAuth(), big.NewInt(84532), "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "2")
	if err != nil {
		t.Fatal(err)
	}
	td.Message["validBefore"] = "90071992547409930" // > 2^53
	m, err := providerTypedDataJSON(td, "primaryType", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m["message"])
	s := string(b)
	if !strings.Contains(s, `"value":1000000`) || !strings.Contains(s, `"validBefore":"90071992547409930"`) {
		t.Fatalf("message %s: small uints must be numbers, large ones strings", s)
	}
	f, priv := newFakeTurnkey(t)
	ks := fakeTurnkeyKeystore(t, f, priv)
	if _, err := ks.fallback.SignTypedData(context.Background(), td); err != nil {
		t.Fatalf("a payload with numeric uints must still hash to the same message: %v", err)
	}
}

// add_product and activate_merchant write on-chain and then sync the backend with an agent-auth
// request. Under Turnkey the second half cannot be signed, so they must refuse before the write,
// not after it has spent gas and left an on-chain product the backend never hears of.
func TestTurnkey_ChainThenRESTToolsRefuseUpFront(t *testing.T) {
	f, priv := newFakeTurnkey(t)
	signerKeys = fakeTurnkeyKeystore(t, f, priv)
	t.Setenv("BASE_RPC_URL", "http://127.0.0.1:1") // any chain access would fail differently
	before := len(f.requests)
	_, _, err := handleAddProduct(context.Background(), nil, addProductInput{MerchantID: "4", ProductID: zero32, CommissionBps: 500,
		EndpointURL: "https://m.example/buy", Name: "x", Category: "chain.wallet"})
	if err == nil || !strings.Contains(err.Error(), "SIGNER_BACKEND=turnkey") || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("add_product under turnkey: want an up-front refusal, got %v", err)
	}
	_, _, err = handleActivateMerchant(context.Background(), nil, activateMerchantInput{MerchantID: "4"})
	if err == nil || !strings.Contains(err.Error(), "SIGNER_BACKEND=turnkey") || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("activate_merchant under turnkey: want an up-front refusal, got %v", err)
	}
	if len(f.requests) != before {
		t.Fatal("a refused merchant tool reached Turnkey")
	}
}
