package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	keyA = "1111111111111111111111111111111111111111111111111111111111111111"
	keyB = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestParseKeystore_MultiKeyExactMatch(t *testing.T) {
	ks, err := parseKeystore("5:0x"+keyA+",9:0x"+keyB, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	k5, err := ks.KeyFor("5")
	if err != nil {
		t.Fatal(err)
	}
	k9, _ := ks.KeyFor("9")
	if crypto.PubkeyToAddress(k5.PublicKey) == crypto.PubkeyToAddress(k9.PublicKey) {
		t.Fatal("agent 5 and 9 must resolve to distinct keys")
	}
	wantA, _ := crypto.HexToECDSA(keyA)
	if crypto.PubkeyToAddress(k5.PublicKey) != crypto.PubkeyToAddress(wantA.PublicKey) {
		t.Fatal("agent 5 resolved to wrong key")
	}
}

func TestParseKeystore_SingleKeyFallback(t *testing.T) {
	ks, err := parseKeystore("", "0x"+keyA)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	k1, err := ks.KeyFor("1")
	if err != nil {
		t.Fatal(err)
	}
	k999, _ := ks.KeyFor("999")
	if crypto.PubkeyToAddress(k1.PublicKey) != crypto.PubkeyToAddress(k999.PublicKey) {
		t.Fatal("fallback must serve every agent id")
	}
}

func TestParseKeystore_AgentKeysMissThenFallback(t *testing.T) {
	ks, _ := parseKeystore("5:0x"+keyA, "0x"+keyB)
	got, err := ks.KeyFor("7")
	if err != nil {
		t.Fatal(err)
	}
	wantB, _ := crypto.HexToECDSA(keyB)
	if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(wantB.PublicKey) {
		t.Fatal("miss must fall back to AGENT_PRIVATE_KEY")
	}
}

func TestParseKeystore_MissNoFallbackErrors(t *testing.T) {
	ks, _ := parseKeystore("5:0x"+keyA, "")
	if _, err := ks.KeyFor("7"); err == nil {
		t.Fatal("expected error for unknown agent with no fallback")
	}
}

func TestParseKeystore_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"no colon":  "5" + keyA,
		"empty id":  ":0x" + keyA,
		"bad hex":   "5:0xZZZZ",
		"duplicate": "5:0x" + keyA + ",5:0x" + keyB,
	}
	for name, env := range cases {
		if _, err := parseKeystore(env, ""); err == nil {
			t.Errorf("%s: expected parse error, got nil", name)
		}
	}
}

func TestParseKeystore_NoKeysErrors(t *testing.T) {
	if _, err := parseKeystore("", ""); err == nil {
		t.Fatal("expected error when no keys configured")
	}
}

func TestKeystore_MultiAgentSignaturesRecoverDistinct(t *testing.T) {
	ks, _ := parseKeystore("5:0x"+keyA+",9:0x"+keyB, "")
	digest := crypto.Keccak256([]byte("test message"))
	sign := func(agentID string) [20]byte {
		k, err := ks.KeyFor(agentID)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := crypto.Sign(digest, k)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := crypto.SigToPub(digest, sig)
		if err != nil {
			t.Fatal(err)
		}
		return crypto.PubkeyToAddress(*pub)
	}
	if sign("5") == sign("9") {
		t.Fatal("distinct agents must produce distinct recovered addresses")
	}
}
