package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecurityAddScript(t *testing.T) {
	got := securityAddScript("AGENT_PRIVATE_KEY", "0xabc")
	want := "add-generic-password -U -s opensouk-signer -a AGENT_PRIVATE_KEY -w 0xabc\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestKeychainWriteSecurity_ErrorNeverHoldsValue(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script stub")
	}
	fake := filepath.Join(t.TempDir(), "security")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncat\ncat >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := securityPath
	securityPath = fake
	t.Cleanup(func() { securityPath = old })
	const secret = "0xdeadbeefcafe"
	err := keychainWriteSecurity(context.Background(), "AGENT_PRIVATE_KEY", secret)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "deadbeefcafe") {
		t.Fatalf("error holds the value: %v", err)
	}
}
