package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const testKeyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

func testKeyAddr(t *testing.T) string {
	t.Helper()
	k, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PubkeyToAddress(k.PublicKey).Hex()
}

func TestParseAgentKey_Forms(t *testing.T) {
	want := testKeyAddr(t)
	for _, in := range []string{"  " + testKeyHex + "  \n", "0x" + strings.ToUpper(testKeyHex), "0X" + testKeyHex} {
		hexKey, addr, err := parseAgentKey(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if hexKey != "0x"+testKeyHex {
			t.Fatalf("hexKey = %q", hexKey)
		}
		if addr.Hex() != want {
			t.Fatalf("addr = %s, want %s", addr.Hex(), want)
		}
	}
}

func TestParseAgentKey_SeedPhrase(t *testing.T) {
	const want = "that looks like a seed phrase. init takes one account's private key: export it from your wallet app (account details → show private key)"
	_, _, err := parseAgentKey("abandon ability able about above absent absorb abstract absurd abuse access accident")
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
}

func TestParseAgentKey_Rejects(t *testing.T) {
	const want = "not a private key: want 64 hex characters, with or without 0x"
	for _, in := range []string{"", "   ", testKeyHex[:63], testKeyHex + "0", strings.Repeat("zz", 32), "0x"} {
		_, _, err := parseAgentKey(in)
		if err == nil || err.Error() != want {
			t.Fatalf("%q: err = %v", in, err)
		}
	}
}

func TestRunInit_KeyNeverPrinted(t *testing.T) {
	var out, errOut bytes.Buffer
	var prompt string
	d := initDeps{
		out: &out, errOut: &errOut,
		isTerminal: func() bool { return true },
		readSecret: func(p string) (string, error) { prompt = p; return "0x" + testKeyHex, nil },
	}
	if code := runInit(context.Background(), nil, d); code == 0 {
		t.Fatal("exit 0 before the rest of init exists")
	}
	if prompt != "Private key of the account that owns your agent (input hidden): " {
		t.Fatalf("prompt = %q", prompt)
	}
	if !strings.Contains(errOut.String()+out.String(), "key for "+testKeyAddr(t)+" read") {
		t.Fatalf("address line missing: out=%q err=%q", out.String(), errOut.String())
	}
	for _, s := range []string{out.String(), errOut.String()} {
		low := strings.ToLower(s)
		if strings.Contains(low, testKeyHex) {
			t.Fatalf("key leaked: %q", s)
		}
	}
}

func TestRunInit_BadKeyExits1(t *testing.T) {
	var out, errOut bytes.Buffer
	d := initDeps{
		out: &out, errOut: &errOut,
		isTerminal: func() bool { return true },
		readSecret: func(string) (string, error) { return "nope", nil },
	}
	if code := runInit(context.Background(), nil, d); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "not a private key: want 64 hex characters, with or without 0x") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRunInit_RefusesWithoutTerminal(t *testing.T) {
	var errOut bytes.Buffer
	d := initDeps{
		out:        &bytes.Buffer{},
		errOut:     &errOut,
		isTerminal: func() bool { return false },
		readSecret: func(string) (string, error) {
			t.Fatal("readSecret called without a terminal")
			return "", nil
		},
	}
	if code := runInit(context.Background(), nil, d); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "run this in your own terminal") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRunInit_BadFlag(t *testing.T) {
	d := initDeps{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, isTerminal: func() bool { return true }}
	if code := runInit(context.Background(), []string{"--nope"}, d); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestDispatchEarly(t *testing.T) {
	if handled, code := dispatchEarly([]string{"opensouk-signer", "init", "--bad"}); !handled || code != 2 {
		t.Fatalf("init: handled=%v code=%d, want true/2", handled, code)
	}
	if handled, _ := dispatchEarly([]string{"opensouk-signer", "policy"}); handled {
		t.Fatal("policy must not be handled early")
	}
	if handled, _ := dispatchEarly([]string{"opensouk-signer"}); handled {
		t.Fatal("no subcommand must not be handled early")
	}
}
