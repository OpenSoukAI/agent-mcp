package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeEnv is a process environment the env file loader reads and writes.
type fakeEnv map[string]string

func (e fakeEnv) lookup(k string) (string, bool) { v, ok := e[k]; return v, ok }
func (e fakeEnv) setenv(k, v string) error       { e[k] = v; return nil }

// writeEnvFile writes body to home/.config/opensouk/signer.env with the given mode.
func writeEnvFile(t *testing.T, home, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(home, ".config", "opensouk", "signer.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func homeAt(dir string) func() (string, error) { return func() (string, error) { return dir, nil } }

func TestLoadEnvFile_NoDefaultFileIsNotAnError(t *testing.T) {
	env := fakeEnv{}
	report, err := loadEnvFile(env.lookup, env.setenv, homeAt(t.TempDir()))
	if err != nil || len(report) != 0 || len(env) != 0 {
		t.Fatalf("a missing default file must be skipped silently: report=%v env=%v err=%v", report, env, err)
	}
}

func TestLoadEnvFile_MissingExplicitFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.env")
	env := fakeEnv{"SIGNER_ENV_FILE": path}
	if _, err := loadEnvFile(env.lookup, env.setenv, homeAt(t.TempDir())); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("SIGNER_ENV_FILE naming a missing file must be refused, naming the path: %v", err)
	}
}

func TestLoadEnvFile_FillsWhatTheClientLeftUnset(t *testing.T) {
	home := t.TempDir()
	path := writeEnvFile(t, home, strings.Join([]string{
		"# agent wallet",
		"",
		"AGENT_PRIVATE_KEY=0x" + testLocalKeyHex,
		"export CHAIN_ID=84532",
		`BASE_RPC_URL="https://sepolia.base.org"`,
		"PRIVY_AUTHORIZATION_KEY='wallet-auth:abc=='",
		"REFERRER_API_URL=https://api.example",
		"REFERRER_AGENT_MCP_URL=https://mcp.example/mcp",
		"MAX_PAYMENT_PER_TX=1000\r",
	}, "\n"), 0o600)
	env := fakeEnv{
		"REFERRER_API_URL":       "https://client.example",    // the client's value wins
		"BASE_RPC_URL":           "",                          // empty counts as unset
		"REFERRER_AGENT_MCP_URL": "${REFERRER_AGENT_MCP_URL}", // so does a reference the client did not expand
	}
	report, err := loadEnvFile(env.lookup, env.setenv, homeAt(home))
	if err != nil {
		t.Fatal(err)
	}
	want := fakeEnv{
		"AGENT_PRIVATE_KEY":       "0x" + testLocalKeyHex,
		"CHAIN_ID":                "84532",
		"BASE_RPC_URL":            "https://sepolia.base.org",
		"PRIVY_AUTHORIZATION_KEY": "wallet-auth:abc==",
		"REFERRER_API_URL":        "https://client.example",
		"REFERRER_AGENT_MCP_URL":  "https://mcp.example/mcp",
		"MAX_PAYMENT_PER_TX":      "1000",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	joined := strings.Join(report, "\n")
	if !strings.Contains(joined, path) || !strings.Contains(joined, "REFERRER_API_URL") {
		t.Fatalf("boot report must name the file and the setting the client overrode: %v", report)
	}
	if strings.Contains(joined, testLocalKeyHex) || strings.Contains(joined, "client.example") {
		t.Fatalf("boot report must name settings, never values: %v", report)
	}
}

func TestLoadEnvFile_ExpandsTildeInSignerEnvFile(t *testing.T) {
	home := t.TempDir()
	writeEnvFile(t, home, "CHAIN_ID=8453\n", 0o600)
	env := fakeEnv{"SIGNER_ENV_FILE": "~/.config/opensouk/signer.env"}
	if _, err := loadEnvFile(env.lookup, env.setenv, homeAt(home)); err != nil || env["CHAIN_ID"] != "8453" {
		t.Fatalf("~/ must resolve to the home directory: CHAIN_ID=%q err=%v", env["CHAIN_ID"], err)
	}
}

func TestLoadEnvFile_RefusesAFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits")
	}
	home := t.TempDir()
	path := writeEnvFile(t, home, "AGENT_PRIVATE_KEY=0x"+testLocalKeyHex+"\n", 0o644)
	env := fakeEnv{}
	_, err := loadEnvFile(env.lookup, env.setenv, homeAt(home))
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) {
		t.Fatalf("a group- or world-readable file must be refused with the fix: %v", err)
	}
	if strings.Contains(err.Error(), testLocalKeyHex) || len(env) != 0 {
		t.Fatalf("a refused file must set nothing and print no value: env=%v err=%v", env, err)
	}
}

func TestLoadEnvFile_RefusesMalformedLinesWithoutEchoingThem(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"no equals", "CHAIN_ID=8453\n0x" + testLocalKeyHex + "\n", "line 2"},
		{"bad key", "AGENT PRIVATE KEY=0x" + testLocalKeyHex + "\n", "line 1"},
		{"duplicate", "AGENT_PRIVATE_KEY=0x" + testLocalKeyHex + "\n\nAGENT_PRIVATE_KEY=0x" + testLocalKeyHex + "\n", "line 3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			writeEnvFile(t, home, c.body, 0o600)
			env := fakeEnv{}
			_, err := loadEnvFile(env.lookup, env.setenv, homeAt(home))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error naming %q, got %v", c.want, err)
			}
			if strings.Contains(err.Error(), testLocalKeyHex) || len(env) != 0 {
				t.Fatalf("a refused file must set nothing and print no value: env=%v err=%v", env, err)
			}
		})
	}
}

// A key line left in the file after moving to a remote backend must still stop the signer.
func TestLoadEnvFile_StaleKeyLineTripsTheRemoteBackendRefusal(t *testing.T) {
	home := t.TempDir()
	writeEnvFile(t, home, "AGENT_PRIVATE_KEY=0x"+testLocalKeyHex+"\n", 0o600)
	env := fakeEnv{"SIGNER_BACKEND": "turnkey", "AGENT_WALLETS": "*:0x0000000000000000000000000000000000000001"}
	if _, err := loadEnvFile(env.lookup, env.setenv, homeAt(home)); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadKeystore(context.Background(), envOf(env), nil)
	if err == nil || !strings.Contains(err.Error(), "AGENT_PRIVATE_KEY") {
		t.Fatalf("want the remote-backend refusal naming AGENT_PRIVATE_KEY, got %v", err)
	}
}
