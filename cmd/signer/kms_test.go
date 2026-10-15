package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
)

// encodeSPKI builds the DER SubjectPublicKeyInfo KMS GetPublicKey returns for a secp256k1 key.
func encodeSPKI(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	return encodeSPKIBytes(pub)
}

// derSign signs digest with key and returns the DER (r,s) KMS would, optionally with high s.
func derSign(t *testing.T, key *ecdsa.PrivateKey, digest [32]byte, highS bool) []byte {
	t.Helper()
	sig, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if highS {
		s = new(big.Int).Sub(secp256k1N, s)
	}
	der, err := asn1.Marshal(ecdsaDERSignature{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type fakeKMS struct {
	keys      map[string]*ecdsa.PrivateKey
	spki      map[string][]byte // overrides GetPublicKey for a key id
	highS     bool
	signCalls int
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	id := *in.KeyId
	if der, ok := f.spki[id]; ok {
		return &kms.GetPublicKeyOutput{PublicKey: der}, nil
	}
	k, ok := f.keys[id]
	if !ok {
		return nil, errors.New("NotFoundException: no such key")
	}
	return &kms.GetPublicKeyOutput{PublicKey: encodeSPKIBytes(&k.PublicKey)}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	k := f.keys[*in.KeyId]
	var d [32]byte
	copy(d[:], in.Message)
	sig, _ := crypto.Sign(d[:], k)
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if f.highS {
		s = new(big.Int).Sub(secp256k1N, s)
	}
	der, _ := asn1.Marshal(ecdsaDERSignature{R: r, S: s})
	return &kms.SignOutput{Signature: der}, nil
}

func encodeSPKIBytes(pub *ecdsa.PublicKey) []byte {
	point := crypto.FromECDSAPub(pub)
	der, _ := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: spkiAlgorithmIdentifier{Algorithm: oidECPublicKeyDER, Parameters: oidSecp256k1DER},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	return der
}

// ── conversion (ported from backend internal/signing/remote_signer_test.go) ──

func TestAddressFromSPKI_MatchesLocalDerivation(t *testing.T) {
	key, _ := crypto.GenerateKey()
	got, err := addressFromSPKI(encodeSPKI(t, &key.PublicKey))
	if err != nil || got != crypto.PubkeyToAddress(key.PublicKey) {
		t.Fatalf("got %s err %v", got.Hex(), err)
	}
}

func TestAddressFromSPKI_RejectsWrongCurve(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if _, err := addressFromSPKI(der); err == nil || !strings.Contains(err.Error(), "secp256k1") {
		t.Fatalf("want a curve refusal naming secp256k1, got %v", err)
	}
}

// digestsForBothV returns one digest whose signature under key has v=0 and one with v=1. Signing
// is deterministic (RFC 6979), so the same digests come back every run and a recovery-id trial
// that skipped one value fails every time rather than half the time.
func digestsForBothV(t *testing.T, key *ecdsa.PrivateKey) [][32]byte {
	t.Helper()
	var byV [2]*[32]byte
	for i := 0; i < 64 && (byV[0] == nil || byV[1] == nil); i++ {
		d := crypto.Keccak256Hash([]byte{byte(i)}, []byte("ref-490 v"))
		sig, err := crypto.Sign(d[:], key)
		if err != nil {
			t.Fatal(err)
		}
		if byV[sig[64]] == nil {
			dd := [32]byte(d)
			byV[sig[64]] = &dd
		}
	}
	if byV[0] == nil || byV[1] == nil {
		t.Fatal("no digest pair covering v=0 and v=1")
	}
	return [][32]byte{*byV[0], *byV[1]}
}

func fixedKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA(testLocalKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEthSigFromDER_RoundTripsAndNormalisesHighS(t *testing.T) {
	key := fixedKey(t)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	for _, digest := range digestsForBothV(t, key) {
		for _, high := range []bool{false, true} {
			sig, err := ethSigFromDER(derSign(t, key, digest, high), digest, addr)
			if err != nil {
				t.Fatalf("highS=%v: %v", high, err)
			}
			if sig[64] > 1 {
				t.Fatalf("v = %d, want 0 or 1 (the crypto.Sign convention)", sig[64])
			}
			if new(big.Int).SetBytes(sig[32:64]).Cmp(secp256k1HalfN) > 0 {
				t.Fatalf("highS=%v: s not normalised", high)
			}
			pub, err := crypto.SigToPub(digest[:], sig)
			if err != nil || crypto.PubkeyToAddress(*pub) != addr {
				t.Fatalf("highS=%v: recovers to the wrong address", high)
			}
		}
	}
}

func TestEthSigFromDER_RejectsOtherKeyAndMalformedDER(t *testing.T) {
	key, _ := crypto.GenerateKey()
	other, _ := crypto.GenerateKey()
	digest := crypto.Keccak256Hash([]byte("x"))
	if _, err := ethSigFromDER(derSign(t, other, digest, false), digest, crypto.PubkeyToAddress(key.PublicKey)); err == nil {
		t.Fatal("a signature from another key must be refused")
	}
	if _, err := ethSigFromDER([]byte{0x30, 0x01, 0x00}, digest, crypto.PubkeyToAddress(key.PublicKey)); err == nil {
		t.Fatal("malformed DER must be refused")
	}
}

// ── kmsSigner ──

func TestKMSSigner_SignsAsTheKMSKey(t *testing.T) {
	key := fixedKey(t)
	for _, high := range []bool{false, true} {
		f := &fakeKMS{keys: map[string]*ecdsa.PrivateKey{"k1": key}, highS: high}
		s, err := newKMSSigner(context.Background(), f, "k1")
		if err != nil {
			t.Fatal(err)
		}
		if s.Address() != crypto.PubkeyToAddress(key.PublicKey) {
			t.Fatalf("address %s", s.Address().Hex())
		}
		for _, digest := range digestsForBothV(t, key) {
			sig, err := s.SignDigest(context.Background(), digest)
			if err != nil {
				t.Fatalf("highS=%v: %v", high, err)
			}
			pub, err := crypto.SigToPub(digest[:], sig)
			if err != nil || crypto.PubkeyToAddress(*pub) != s.Address() {
				t.Fatalf("highS=%v: signature does not recover to the KMS key", high)
			}
		}
	}
}

// hangingKMS never answers; only the caller's deadline ends a request.
type hangingKMS struct{}

func (hangingKMS) GetPublicKey(ctx context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (hangingKMS) Sign(ctx context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestKMSSigner_BoundsEachCall(t *testing.T) {
	prev := kmsCallTimeout
	kmsCallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { kmsCallTimeout = prev })

	within := func(name string, call func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s on a stalled KMS: want a deadline error, got %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s on a stalled KMS did not return: no per-call deadline", name)
		}
	}
	within("GetPublicKey", func() error {
		_, err := newKMSSigner(context.Background(), hangingKMS{}, "k1")
		return err
	})
	within("Sign", func() error {
		_, err := (&kmsSigner{api: hangingKMS{}, keyID: "k1"}).SignDigest(context.Background(), [32]byte{1})
		return err
	})
}

// ── loadKeystore ──

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const arnA = "arn:aws:kms:eu-central-1:111122223333:key/aaaaaaaa-1111-2222-3333-444444444444"
const arnB = "arn:aws:kms:eu-central-1:111122223333:key/bbbbbbbb-1111-2222-3333-444444444444"

func kmsFactory(f *fakeKMS) func(context.Context) (kmsAPI, error) {
	return func(context.Context) (kmsAPI, error) { return f, nil }
}

func TestLoadKeystore_DefaultIsLocal(t *testing.T) {
	ks, _, err := loadKeystore(context.Background(), envOf(map[string]string{"AGENT_KEYS": "7:0x" + testLocalKeyHex}), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ks.KeyFor("7")
	if _, ok := s.(*localSigner); !ok {
		t.Fatalf("unset SIGNER_BACKEND must give local signers, got %T", s)
	}
}

func TestLoadKeystore_KMS(t *testing.T) {
	ka, _ := crypto.GenerateKey()
	kb, _ := crypto.GenerateKey()
	f := &fakeKMS{keys: map[string]*ecdsa.PrivateKey{arnA: ka, arnB: kb}}
	ks, addrs, err := loadKeystore(context.Background(), envOf(map[string]string{
		"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:" + arnA + ", *:" + arnB,
	}), kmsFactory(f))
	if err != nil {
		t.Fatal(err)
	}
	s7, _ := ks.KeyFor("7")
	other, _ := ks.KeyFor("99")
	if s7.Address() != crypto.PubkeyToAddress(ka.PublicKey) || other.Address() != crypto.PubkeyToAddress(kb.PublicKey) {
		t.Fatal("agent 7 must resolve to key A and any other id to the * key B")
	}
	if len(addrs) != 2 || !strings.Contains(strings.Join(addrs, " "), crypto.PubkeyToAddress(ka.PublicKey).Hex()) {
		t.Fatalf("boot report %v must name each KMS key's address", addrs)
	}
}

func TestLoadKeystore_Refusals(t *testing.T) {
	ka, _ := crypto.GenerateKey()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p256DER, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	f := &fakeKMS{keys: map[string]*ecdsa.PrivateKey{arnA: ka}, spki: map[string][]byte{arnB: p256DER}}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"unknown backend", map[string]string{"SIGNER_BACKEND": "vault"}, "SIGNER_BACKEND"},
		{"kms with AGENT_KEYS", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:" + arnA, "AGENT_KEYS": "7:0x" + testLocalKeyHex}, "AGENT_KEYS"},
		{"kms with AGENT_PRIVATE_KEY", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:" + arnA, "AGENT_PRIVATE_KEY": "0x" + testLocalKeyHex}, "AGENT_PRIVATE_KEY"},
		{"local with AGENT_WALLETS", map[string]string{"AGENT_KEYS": "7:0x" + testLocalKeyHex, "AGENT_WALLETS": "7:" + arnA}, "AGENT_WALLETS"},
		{"kms without wallets", map[string]string{"SIGNER_BACKEND": "kms"}, "AGENT_WALLETS"},
		{"duplicate id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:" + arnA + ",7:" + arnA}, "duplicate"},
		{"bad id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "seven:" + arnA}, "agent id"},
		{"leading zero id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "007:" + arnA}, "agent id"},
		{"signed id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "+7:" + arnA}, "agent id"},
		{"negative id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "-7:" + arnA}, "agent id"},
		{"missing key id", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:"}, "key id"},
		{"wrong curve at boot", map[string]string{"SIGNER_BACKEND": "kms", "AGENT_WALLETS": "7:" + arnB}, "secp256k1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := loadKeystore(context.Background(), envOf(c.env), kmsFactory(f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error naming %q, got %v", c.want, err)
			}
		})
	}
}
