package main

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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
		lookup: func(k string) (string, bool) {
			if k == "SIGNER_ENV_FILE" {
				return filepath.Join(t.TempDir(), "signer.env"), true
			}
			return "", false
		},
		identity: func(context.Context, int64, string, *big.Int) (common.Address, common.Address, error) {
			return common.HexToAddress(testKeyAddr(t)), common.Address{}, nil
		},
	}
	if code := runInit(context.Background(), []string{"--agent-id", "7"}, d); code != 0 {
		t.Fatalf("exit = %d", code)
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

type identityCall struct {
	chainID int64
	rpcURL  string
	agentID *big.Int
}

func identityDeps(t *testing.T, errOut *bytes.Buffer, env map[string]string, line string, owner, bound common.Address, idErr error, calls *[]identityCall) initDeps {
	t.Helper()
	return initDeps{
		out: &bytes.Buffer{}, errOut: errOut,
		isTerminal: func() bool { return true },
		readSecret: func(string) (string, error) { return testKeyHex, nil },
		readLine: func(p string) (string, error) {
			if p != "Agent ID (the # on your OpenSouk dashboard): " {
				t.Fatalf("prompt = %q", p)
			}
			return line, nil
		},
		lookup: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		home:   func() (string, error) { return t.TempDir(), nil },
		identity: func(_ context.Context, c int64, u string, id *big.Int) (common.Address, common.Address, error) {
			*calls = append(*calls, identityCall{c, u, id})
			return owner, bound, idErr
		},
	}
}

func TestRunInit_AsksForAgentID(t *testing.T) {
	var calls []identityCall
	var errOut bytes.Buffer
	key := common.HexToAddress(testKeyAddr(t))
	d := identityDeps(t, &errOut, nil, "1174968", key, common.Address{}, nil, &calls)
	runInit(context.Background(), nil, d)
	if len(calls) != 1 || calls[0].agentID.Cmp(big.NewInt(1174968)) != 0 || calls[0].chainID != 8453 || calls[0].rpcURL != "https://mainnet.base.org" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRunInit_BadAgentID(t *testing.T) {
	for _, in := range []string{"", "abc", "0", "-3", "1.5"} {
		var calls []identityCall
		var errOut bytes.Buffer
		d := identityDeps(t, &errOut, nil, in, common.Address{}, common.Address{}, nil, &calls)
		if code := runInit(context.Background(), nil, d); code != 2 || len(calls) != 0 {
			t.Fatalf("%q: exit = %d calls = %d", in, code, len(calls))
		}
	}
}

func TestRunInit_OwnerOrBoundAccepted(t *testing.T) {
	key := common.HexToAddress(testKeyAddr(t))
	other := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	for name, ob := range map[string][2]common.Address{"owner": {key, common.Address{}}, "bound": {other, key}} {
		var calls []identityCall
		var errOut bytes.Buffer
		d := identityDeps(t, &errOut, nil, "5", ob[0], ob[1], nil, &calls)
		runInit(context.Background(), nil, d)
		if len(calls) != 1 {
			t.Fatalf("%s: identity calls = %d", name, len(calls))
		}
		d.lookup = func(k string) (string, bool) {
			if k == "SIGNER_ENV_FILE" {
				return filepath.Join(t.TempDir(), "signer.env"), true
			}
			return "", false
		}
		if code := runInit(context.Background(), []string{"--agent-id", "5"}, d); code != 0 || strings.Contains(errOut.String(), "neither the owner nor the bound wallet") {
			t.Fatalf("%s not accepted: exit %d %q", name, code, errOut.String())
		}
	}
}

func TestRunInit_WrongOwnerWritesNothing(t *testing.T) {
	owner := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	var calls []identityCall
	var errOut bytes.Buffer
	d := identityDeps(t, &errOut, nil, "5", owner, common.Address{}, nil, &calls)
	home, _ := d.home()
	d.home = func() (string, error) { return home, nil }
	if code := runInit(context.Background(), nil, d); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	msg := errOut.String()
	for _, want := range []string{"key " + testKeyAddr(t), "owner " + owner.Hex(), "sign_agent_wallet_set"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in %q", want, msg)
		}
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Fatalf("wrote under home: %v", entries)
	}
}

func TestRunInit_ChainFlags(t *testing.T) {
	var calls []identityCall
	var errOut bytes.Buffer
	d := identityDeps(t, &errOut, map[string]string{"CHAIN_ID": "1", "BASE_RPC_URL": "http://env"}, "5", common.Address{}, common.Address{}, nil, &calls)
	runInit(context.Background(), []string{"--chain-id", "84532", "--rpc-url", "http://x"}, d)
	if len(calls) != 1 || calls[0].chainID != 84532 || calls[0].rpcURL != "http://x" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRunInit_ChainEnvFallback(t *testing.T) {
	var calls []identityCall
	var errOut bytes.Buffer
	d := identityDeps(t, &errOut, map[string]string{"CHAIN_ID": "84532", "BASE_RPC_URL": "http://env"}, "5", common.Address{}, common.Address{}, nil, &calls)
	runInit(context.Background(), []string{"--agent-id", "5"}, d)
	if len(calls) != 1 || calls[0].chainID != 84532 || calls[0].rpcURL != "http://env" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRunInit_ChainReadFails(t *testing.T) {
	var calls []identityCall
	var errOut bytes.Buffer
	d := identityDeps(t, &errOut, nil, "5", common.Address{}, common.Address{}, errors.New("boom"), &calls)
	home, _ := d.home()
	d.home = func() (string, error) { return home, nil }
	if code := runInit(context.Background(), nil, d); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errOut.String(), "could not check the identity on chain 8453: boom") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("wrote under home: %v", entries)
	}
}

func TestRunInit_BadAgentIDNeverEchoed(t *testing.T) {
	var calls []identityCall
	var errOut bytes.Buffer
	d := identityDeps(t, &errOut, nil, testKeyHex, common.Address{}, common.Address{}, nil, &calls)
	var out bytes.Buffer
	d.out = &out
	if code := runInit(context.Background(), nil, d); code != 2 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(strings.ToLower(out.String()+errOut.String()), testKeyHex) {
		t.Fatalf("key echoed: %q", errOut.String())
	}
}

func storageDeps(t *testing.T, goos string) (d initDeps, out, errOut *bytes.Buffer, envPath string) {
	t.Helper()
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	envPath = filepath.Join(t.TempDir(), "sub", "signer.env")
	d = initDeps{
		out: out, errOut: errOut, goos: goos,
		isTerminal: func() bool { return true },
		readSecret: func(string) (string, error) { return testKeyHex, nil },
		lookup: func(k string) (string, bool) {
			if k == "SIGNER_ENV_FILE" {
				return envPath, true
			}
			return "", false
		},
		home: func() (string, error) { return t.TempDir(), nil },
		identity: func(context.Context, int64, string, *big.Int) (common.Address, common.Address, error) {
			return common.HexToAddress(testKeyAddr(t)), common.Address{}, nil
		},
		keychainWrite: func(context.Context, string, string) error { t.Fatal("keychain used"); return nil },
		keychainRead:  func(context.Context, string) (string, bool, error) { return "", false, nil },
	}
	return d, out, errOut, envPath
}

func TestRunInit_WritesEnvFile(t *testing.T) {
	d, out, errOut, path := storageDeps(t, "linux")
	if code := runInit(context.Background(), []string{"--agent-id", "7"}, d); code != 0 {
		t.Fatalf("exit = %d %q", code, errOut.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "AGENT_PRIVATE_KEY=0x"+testKeyHex+"\n" {
		t.Fatalf("file = %q err = %v", got, err)
	}
	for _, want := range []string{"stored AGENT_PRIVATE_KEY in " + path, "restart your MCP client so the signer picks it up"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
	if strings.Contains(out.String()+errOut.String(), testKeyHex) {
		t.Fatal("key leaked")
	}
}

func TestRunInit_ExistingKeyNeedsForce(t *testing.T) {
	d, _, errOut, path := storageDeps(t, "linux")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const old = "AGENT_PRIVATE_KEY=0x" + "11111111111111111111111111111111111111111111111111111111111111aa\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runInit(context.Background(), []string{"--agent-id", "7"}, d); code != 1 || !strings.Contains(errOut.String(), "--force") {
		t.Fatalf("exit = %d %q", code, errOut.String())
	}
	if got, _ := os.ReadFile(path); string(got) != old {
		t.Fatalf("file changed: %q", got)
	}
	errOut.Reset()
	if code := runInit(context.Background(), []string{"--agent-id", "7", "--force"}, d); code != 0 {
		t.Fatalf("--force exit = %d %q", code, errOut.String())
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), testKeyHex) {
		t.Fatalf("file = %q", got)
	}
}

func TestRunInit_KeychainOnMac(t *testing.T) {
	d, out, errOut, path := storageDeps(t, "darwin")
	var acct, val string
	d.keychainWrite = func(_ context.Context, a, v string) error { acct, val = a, v; return nil }
	if code := runInit(context.Background(), []string{"--agent-id", "7", "--keychain"}, d); code != 0 {
		t.Fatalf("exit = %d %q", code, errOut.String())
	}
	if acct != "AGENT_PRIVATE_KEY" || val != "0x"+testKeyHex {
		t.Fatalf("keychainWrite(%q, ...)", acct)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("env file written")
	}
	if !strings.Contains(out.String(), "Keychain") || strings.Contains(out.String()+errOut.String(), testKeyHex) {
		t.Fatalf("out = %q err = %q", out.String(), errOut.String())
	}
}

func keychainStored(t *testing.T, value string, found bool, readErr error, args ...string) (code int, wrote bool, errOut string) {
	t.Helper()
	d, _, e, _ := storageDeps(t, "darwin")
	d.keychainRead = func(context.Context, string) (string, bool, error) { return value, found, readErr }
	d.keychainWrite = func(context.Context, string, string) error { wrote = true; return nil }
	code = runInit(context.Background(), append([]string{"--agent-id", "7", "--keychain"}, args...), d)
	return code, wrote, e.String()
}

func TestRunInit_KeychainExistingKeyNeedsForce(t *testing.T) {
	code, wrote, errOut := keychainStored(t, "0xoldsecretvalue", true, nil)
	if code != 1 || wrote || !strings.Contains(errOut, "--force") || !strings.Contains(errOut, keychainService) || strings.Contains(errOut, "oldsecretvalue") {
		t.Fatalf("exit = %d wrote = %v %q", code, wrote, errOut)
	}
}

func TestRunInit_KeychainExistingKeyForced(t *testing.T) {
	if code, wrote, errOut := keychainStored(t, "0xold", true, nil, "--force"); code != 0 || !wrote {
		t.Fatalf("exit = %d wrote = %v %q", code, wrote, errOut)
	}
}

func TestRunInit_KeychainNoItemOrPlaceholderWrites(t *testing.T) {
	for _, c := range []struct {
		v     string
		found bool
	}{{"", false}, {"", true}, {keyPlaceholder, true}} {
		if code, wrote, errOut := keychainStored(t, c.v, c.found, nil); code != 0 || !wrote {
			t.Fatalf("%+v: exit = %d wrote = %v %q", c, code, wrote, errOut)
		}
	}
}

func TestRunInit_KeychainReadErrorExits1(t *testing.T) {
	code, wrote, errOut := keychainStored(t, "0xleak", true, errors.New("locked"))
	if code != 1 || wrote || !strings.Contains(errOut, "locked") || strings.Contains(errOut, "leak") {
		t.Fatalf("exit = %d wrote = %v %q", code, wrote, errOut)
	}
}

func TestRunInit_KeychainFailureExits1(t *testing.T) {
	d, _, errOut, _ := storageDeps(t, "darwin")
	d.keychainWrite = func(context.Context, string, string) error { return errors.New("denied") }
	if code := runInit(context.Background(), []string{"--agent-id", "7", "--keychain"}, d); code != 1 || !strings.Contains(errOut.String(), "denied") {
		t.Fatalf("exit = %d %q", code, errOut.String())
	}
}

func TestRunInit_KeychainElsewhere(t *testing.T) {
	d, _, errOut, path := storageDeps(t, "linux")
	if code := runInit(context.Background(), []string{"--agent-id", "7", "--keychain"}, d); code != 2 || !strings.Contains(errOut.String(), "--keychain is macOS only") {
		t.Fatalf("exit = %d %q", code, errOut.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("env file written")
	}
}
