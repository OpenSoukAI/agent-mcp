package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyPlaceholder is the value the setup guides ship in signer.env; it counts as empty.
const keyPlaceholder = "REPLACE_WITH_AGENT_KEY"

var errKeyExists = errors.New("signer.env already holds AGENT_PRIVATE_KEY")

// mergeEnvKey sets key=value in an env file's text, changing only that line and keeping every
// other line, comment and the order. The line is edited in place (keeping any "export "), or
// appended when absent. An existing real value is kept unless force is set. Errors name line
// numbers only.
func mergeEnvKey(existing []byte, key, value string, force bool) ([]byte, error) {
	entries, err := parseEnvFile(existing)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e[0] == key && e[1] != "" && e[1] != keyPlaceholder && !force {
			return nil, errKeyExists
		}
	}

	lines := strings.Split(string(existing), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k, _, _ := strings.Cut(strings.TrimPrefix(trimmed, "export "), "=")
		if strings.TrimSpace(k) != key {
			continue
		}
		lines[i] = line[:strings.Index(line, "=")+1] + value
		return []byte(strings.Join(lines, "\n")), nil
	}

	out := string(existing)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return []byte(out + key + "=" + value + "\n"), nil
}

// envFilePath resolves the env file as loadEnvFile does: SIGNER_ENV_FILE (a leading "~/"
// expands), else the default under the home directory.
func envFilePath(lookup func(string) (string, bool), home func() (string, error)) (string, error) {
	path, _ := lookup("SIGNER_ENV_FILE")
	path = strings.TrimSpace(path)
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		dir, err := home()
		if err != nil {
			return "", fmt.Errorf("SIGNER_ENV_FILE %s: %w", path, err)
		}
		return filepath.Join(dir, rest), nil
	}
	if path != "" {
		return path, nil
	}
	dir, err := home()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, defaultEnvFile), nil
}

// writeEnvFileAtomic writes data to path with mode 0600, creating the directory with 0700. The
// rename keeps a failed write from leaving a half-written key file.
func writeEnvFileAtomic(path string, data []byte) (err error) {
	// A symlinked env file is a supported setup: write to the link's target so the link and the
	// secret's chosen location survive.
	if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		resolved, rerr := filepath.EvalSymlinks(path)
		if rerr != nil {
			return fmt.Errorf("%s is a symlink to a missing target: create the target or remove the link", path)
		}
		path = resolved
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".signer.env-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
