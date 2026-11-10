package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

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
