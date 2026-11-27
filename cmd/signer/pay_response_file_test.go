package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain keeps every pay test's saved bodies out of the real home directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "signer-responses-")
	if err != nil {
		panic(err)
	}
	os.Setenv(responseDirEnv, dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestPayForProduct_SavesTheFullBodyOfALargeResponse(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(responseDirEnv, dir)
	body := paidBody(`,"resource":"` + strings.Repeat("a", 3*maxResponseBytes) + `"`)
	out, _, err := payWith(t, merchantOpts{paymentBody: body, paymentContentType: "application/json"}, nil)
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	if !out.ResponseTruncated {
		t.Fatal("fixture: the inline response must be truncated")
	}
	if out.ResponseFileError != "" {
		t.Fatalf("response_file_error = %q", out.ResponseFileError)
	}
	want := filepath.Join(dir, "84532-"+strings.ToLower(out.TxHash)+".json")
	if out.ResponseFile != want {
		t.Fatalf("response_file = %q, want %q", out.ResponseFile, want)
	}
	got, err := os.ReadFile(out.ResponseFile)
	if err != nil {
		t.Fatalf("read response_file: %v", err)
	}
	if string(got) != body {
		t.Errorf("response_file holds %d bytes, want the full %d-byte body", len(got), len(body))
	}
	info, err := os.Stat(out.ResponseFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("response_file mode = %o, want 600", perm)
	}
}

func TestPayForProduct_SavesASmallResponseToo(t *testing.T) {
	t.Setenv(responseDirEnv, t.TempDir())
	body := paidBody(`,"resource":"small"`)
	out, _, err := payWith(t, merchantOpts{paymentBody: body}, nil)
	if err != nil {
		t.Fatalf("handlePayForProduct: %v", err)
	}
	got, err := os.ReadFile(out.ResponseFile)
	if err != nil || string(got) != body {
		t.Fatalf("response_file = %q (%v), want the body", got, err)
	}
}

func TestPayForProduct_AFailedSaveDoesNotFailThePurchase(t *testing.T) {
	// A regular file where the folder should be: MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(responseDirEnv, blocker)
	body := paidBody(`,"resource":"x"`)
	out, _, err := payWith(t, merchantOpts{paymentBody: body}, nil)
	if err != nil {
		t.Fatalf("a settled purchase must succeed even when saving fails: %v", err)
	}
	if out.EscrowID == "" || out.Response != body {
		t.Errorf("purchase output incomplete: escrow %q, response %q", out.EscrowID, out.Response)
	}
	if out.ResponseFile != "" || out.ResponseFileError == "" {
		t.Errorf("response_file = %q, response_file_error = %q; want no path and an error", out.ResponseFile, out.ResponseFileError)
	}
}

func TestResponseDir_DefaultsUnderHome(t *testing.T) {
	t.Setenv(responseDirEnv, "")
	dir, err := responseDir(func() (string, error) { return "/home/agent", nil })
	if err != nil || dir != filepath.Join("/home/agent", ".config", "opensouk", "responses") {
		t.Fatalf("responseDir = %q, %v", dir, err)
	}
	if _, err := responseDir(func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Fatal("no override and no home must be an error")
	}
}

func TestResponseExt(t *testing.T) {
	for ct, want := range map[string]string{
		"application/json":                ".json",
		"application/json; charset=utf-8": ".json",
		"application/problem+json":        ".json",
		"text/csv":                        ".csv",
		"text/html; charset=utf-8":        ".html",
		"text/plain":                      ".txt",
		"application/pdf":                 ".bin",
		"":                                ".bin",
	} {
		if got := responseExt(ct); got != want {
			t.Errorf("responseExt(%q) = %q, want %q", ct, got, want)
		}
	}
}
