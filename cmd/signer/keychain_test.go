package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeKeychain answers lookups from items and records which accounts were asked for.
type fakeKeychain struct {
	items  map[string]string
	failOn string
	asked  []string
}

func (k *fakeKeychain) read(_ context.Context, account string) (string, bool, error) {
	k.asked = append(k.asked, account)
	if account == k.failOn {
		return "", false, errors.New("User interaction is not allowed.")
	}
	v, ok := k.items[account]
	return v, ok, nil
}

func TestLoadKeychain_SkippedOffMacOS(t *testing.T) {
	kc := &fakeKeychain{items: map[string]string{"AGENT_PRIVATE_KEY": "0x" + testLocalKeyHex}}
	env := fakeEnv{}
	for _, goos := range []string{"linux", "windows", "freebsd"} {
		report, err := loadKeychain(context.Background(), goos, env.lookup, env.setenv, kc.read)
		if err != nil || len(report) != 0 {
			t.Fatalf("%s: want no report and no error, got %v %v", goos, report, err)
		}
	}
	if len(kc.asked) != 0 || len(env) != 0 {
		t.Fatalf("the Keychain must not be read off macOS: asked=%v env=%v", kc.asked, env)
	}
}

func TestLoadKeychain_FillsWhatIsUnset(t *testing.T) {
	kc := &fakeKeychain{items: map[string]string{
		"AGENT_PRIVATE_KEY":       "0x" + testLocalKeyHex,
		"PRIVY_APP_SECRET":        "keychain-secret",
		"PRIVY_AUTHORIZATION_KEY": "wallet-auth:kc==",
		"TURNKEY_API_PRIVATE_KEY": "kc-turnkey",
	}}
	env := fakeEnv{
		"PRIVY_APP_SECRET":        "client-secret",              // set by the client or signer.env: wins
		"PRIVY_AUTHORIZATION_KEY": "",                           // empty counts as unset
		"TURNKEY_API_PRIVATE_KEY": "${TURNKEY_API_PRIVATE_KEY}", // so does an unexpanded reference
	}
	report, err := loadKeychain(context.Background(), "darwin", env.lookup, env.setenv, kc.read)
	if err != nil {
		t.Fatal(err)
	}
	want := fakeEnv{
		"AGENT_PRIVATE_KEY":       "0x" + testLocalKeyHex,
		"PRIVY_APP_SECRET":        "client-secret",
		"PRIVY_AUTHORIZATION_KEY": "wallet-auth:kc==",
		"TURNKEY_API_PRIVATE_KEY": "kc-turnkey",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if _, ok := env["AGENT_KEYS"]; ok {
		t.Error("a setting with no Keychain item must stay unset")
	}
	joined := strings.Join(report, "\n")
	if !strings.Contains(joined, "Keychain") || !strings.Contains(joined, "AGENT_PRIVATE_KEY") || !strings.Contains(joined, "PRIVY_APP_SECRET") {
		t.Fatalf("boot report must name what came from the Keychain and what was overridden: %v", report)
	}
	for _, v := range []string{testLocalKeyHex, "secret", "kc==", "kc-turnkey"} {
		if strings.Contains(joined, v) {
			t.Fatalf("boot report must never print a value: %v", report)
		}
	}
}

func TestLoadKeychain_AsksOnlyForSecretSettings(t *testing.T) {
	kc := &fakeKeychain{}
	env := fakeEnv{}
	if _, err := loadKeychain(context.Background(), "darwin", env.lookup, env.setenv, kc.read); err != nil {
		t.Fatal(err)
	}
	slices.Sort(kc.asked)
	want := []string{"AGENT_KEYS", "AGENT_PRIVATE_KEY", "CDP_API_KEY_SECRET", "CDP_WALLET_SECRET", "PRIVY_APP_SECRET", "PRIVY_AUTHORIZATION_KEY", "TURNKEY_API_PRIVATE_KEY"}
	if !slices.Equal(kc.asked, want) {
		t.Fatalf("asked for %v, want exactly %v", kc.asked, want)
	}
}

// A locked Keychain on a headless Mac must not stop a signer configured some other way.
func TestLoadKeychain_AReadFailureIsReportedAndStopsFurtherReads(t *testing.T) {
	kc := &fakeKeychain{failOn: keychainSettings[0], items: map[string]string{keychainSettings[1]: "x"}}
	env := fakeEnv{}
	report, err := loadKeychain(context.Background(), "darwin", env.lookup, env.setenv, kc.read)
	if err != nil {
		t.Fatalf("a Keychain read failure must not be fatal: %v", err)
	}
	if len(kc.asked) != 1 || len(env) != 0 {
		t.Fatalf("after one failure the Keychain must not be read again: asked=%v env=%v", kc.asked, env)
	}
	if !strings.Contains(strings.Join(report, "\n"), "User interaction is not allowed.") {
		t.Fatalf("boot report must carry the failure: %v", report)
	}
}

// fakeSecurity installs a shell script as the security command for one test.
func fakeSecurity(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "security")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := securityPath
	securityPath = path
	t.Cleanup(func() { securityPath = old })
}

func TestSecurityRead_ReturnsTheItemWithoutItsNewline(t *testing.T) {
	fakeSecurity(t, `[ "$*" = "find-generic-password -s opensouk-signer -a AGENT_PRIVATE_KEY -w" ] || exit 9
printf '0x`+testLocalKeyHex+`\n'`)
	v, found, err := securityRead(context.Background(), "AGENT_PRIVATE_KEY")
	if err != nil || !found || v != "0x"+testLocalKeyHex {
		t.Fatalf("got %q found=%v err=%v", v, found, err)
	}
}

func TestSecurityRead_ExitCode44IsNotFound(t *testing.T) {
	fakeSecurity(t, `echo "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." >&2; exit 44`)
	v, found, err := securityRead(context.Background(), "AGENT_PRIVATE_KEY")
	if err != nil || found || v != "" {
		t.Fatalf("exit 44 must read as no item: %q found=%v err=%v", v, found, err)
	}
}

func TestSecurityRead_OtherFailuresCarryStderr(t *testing.T) {
	fakeSecurity(t, `echo "security: User interaction is not allowed." >&2; exit 36`)
	_, found, err := securityRead(context.Background(), "AGENT_PRIVATE_KEY")
	if err == nil || found || !strings.Contains(err.Error(), "User interaction is not allowed.") || !strings.Contains(err.Error(), "AGENT_PRIVATE_KEY") {
		t.Fatalf("want an error naming the setting and the cause, got found=%v err=%v", found, err)
	}
}

func TestSecurityRead_TimesOutOnAWaitingDialog(t *testing.T) {
	fakeSecurity(t, `exec sleep 10`)
	old := keychainTimeout
	keychainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { keychainTimeout = old })
	start := time.Now()
	_, _, err := securityRead(context.Background(), "AGENT_PRIVATE_KEY")
	if err == nil || !strings.Contains(err.Error(), "dialog") {
		t.Fatalf("want a timeout pointing at a Keychain dialog, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the timeout did not stop the read")
	}
}
