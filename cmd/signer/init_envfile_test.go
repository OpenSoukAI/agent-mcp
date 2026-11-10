package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testKeyValue = "0xabc123"

func TestMergeEnvKey_NewFile(t *testing.T) {
	got, err := mergeEnvKey(nil, "AGENT_PRIVATE_KEY", testKeyValue, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "AGENT_PRIVATE_KEY=" + testKeyValue + "\n"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMergeEnvKey_AppendsWhenAbsent(t *testing.T) {
	got, err := mergeEnvKey([]byte("# mine\nCHAIN_ID=8453"), "AGENT_PRIVATE_KEY", testKeyValue, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "# mine\nCHAIN_ID=8453\nAGENT_PRIVATE_KEY=" + testKeyValue + "\n"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMergeEnvKey_ReplacesPlaceholderKeepsRest(t *testing.T) {
	in := "# mine\nBASE_RPC_URL=x\nAGENT_PRIVATE_KEY=REPLACE_WITH_AGENT_KEY\nCHAIN_ID=8453\n"
	got, err := mergeEnvKey([]byte(in), "AGENT_PRIVATE_KEY", testKeyValue, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "# mine\nBASE_RPC_URL=x\nAGENT_PRIVATE_KEY=" + testKeyValue + "\nCHAIN_ID=8453\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMergeEnvKey_EmptyValueAndExport(t *testing.T) {
	got, err := mergeEnvKey([]byte("A=1\nexport AGENT_PRIVATE_KEY=\"\"\nB=2\n"), "AGENT_PRIVATE_KEY", testKeyValue, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "A=1\nexport AGENT_PRIVATE_KEY=" + testKeyValue + "\nB=2\n"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMergeEnvKey_RefusesRealKey(t *testing.T) {
	in := []byte("A=1\nAGENT_PRIVATE_KEY=0xdeadbeef\n")
	got, err := mergeEnvKey(in, "AGENT_PRIVATE_KEY", testKeyValue, false)
	if !errors.Is(err, errKeyExists) || got != nil {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = mergeEnvKey(in, "AGENT_PRIVATE_KEY", testKeyValue, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := "A=1\nAGENT_PRIVATE_KEY=" + testKeyValue + "\n"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMergeEnvKey_MalformedFile(t *testing.T) {
	got, err := mergeEnvKey([]byte("A=1\ngarbage\n"), "AGENT_PRIVATE_KEY", testKeyValue, true)
	if err == nil || got != nil {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "garbage") {
		t.Fatalf("error should name the line only: %v", err)
	}
}

func TestEnvFilePath(t *testing.T) {
	home := func() (string, error) { return "/h", nil }
	set := func(k string) (string, bool) {
		if k == "SIGNER_ENV_FILE" {
			return "~/x.env", true
		}
		return "", false
	}
	if got, err := envFilePath(set, home); err != nil || got != filepath.Join("/h", "x.env") {
		t.Fatalf("got %q, %v", got, err)
	}
	unset := func(string) (string, bool) { return "", false }
	if got, err := envFilePath(unset, home); err != nil || got != filepath.Join("/h", ".config", "opensouk", "signer.env") {
		t.Fatalf("got %q, %v", got, err)
	}
	abs := func(string) (string, bool) { return "/etc/s.env", true }
	if got, err := envFilePath(abs, home); err != nil || got != "/etc/s.env" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWriteEnvFile_TightensMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "signer.env")
	if err := writeEnvFileAtomic(path, []byte("X=1\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvFileAtomic(path, []byte("X=2\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "X=2\n" {
		t.Fatalf("content %q", b)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
}

func TestWriteEnvFile_WritesThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "secrets", "real.env")
	link := filepath.Join(dir, "home", "signer.env")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvFileAtomic(link, []byte("X=2\n")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "X=2\n" {
		t.Fatalf("target content %q", b)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o600 {
		t.Fatalf("target mode %v", fi.Mode().Perm())
	}
	for _, d := range []string{filepath.Dir(target), filepath.Dir(link)} {
		if es, _ := os.ReadDir(d); len(es) != 1 {
			t.Fatalf("unexpected files in %s: %v", d, es)
		}
	}
}

func TestWriteEnvFile_DanglingSymlinkFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone", "real.env")
	link := filepath.Join(dir, "signer.env")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	err := writeEnvFileAtomic(link, []byte("X=1\n"))
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("want error naming %s, got %v", link, err)
	}
	if _, serr := os.Stat(filepath.Dir(missing)); serr == nil {
		t.Fatal("dangling target's directory was created")
	}
	if fi, _ := os.Lstat(link); fi == nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link was replaced")
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("unexpected files: %v", es)
	}
}
