package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// defaultEnvFile is where the signer looks for its settings when SIGNER_ENV_FILE is unset,
// relative to the home directory.
var defaultEnvFile = filepath.Join(".config", "opensouk", "signer.env")

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// loadEnvFile fills the environment from the signer's env file, for each setting the MCP client
// left empty or passed as a reference it did not expand. It returns lines for the boot log, which
// name settings and never values. A missing file is skipped unless SIGNER_ENV_FILE names it.
func loadEnvFile(lookup func(string) (string, bool), setenv func(string, string) error, home func() (string, error)) ([]string, error) {
	path, _ := lookup("SIGNER_ENV_FILE")
	path, explicit := strings.TrimSpace(path), true
	if path == "" {
		dir, err := home()
		if err != nil {
			return nil, nil
		}
		path, explicit = filepath.Join(dir, defaultEnvFile), false
	} else if rest, ok := strings.CutPrefix(path, "~/"); ok {
		dir, err := home()
		if err != nil {
			return nil, fmt.Errorf("SIGNER_ENV_FILE %s: %w", path, err)
		}
		path = filepath.Join(dir, rest)
	}

	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (mode %04o): run chmod 600 %s", path, perm, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	entries, err := parseEnvFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	var loaded, overridden []string
	for _, e := range entries {
		if v, ok := lookup(e[0]); ok && strings.TrimSpace(v) != "" && !unexpandedRef.MatchString(strings.TrimSpace(v)) {
			overridden = append(overridden, e[0])
			continue
		}
		if err := setenv(e[0], e[1]); err != nil {
			return nil, fmt.Errorf("set %s: %w", e[0], err)
		}
		loaded = append(loaded, e[0])
	}
	report := []string{fmt.Sprintf("settings from %s: %s", path, strings.Join(loaded, ", "))}
	for _, k := range overridden {
		report = append(report, fmt.Sprintf("%s is set in both %s and the MCP client's config; using the client's", k, path))
	}
	return report, nil
}

// parseEnvFile reads KEY=value lines. Blank lines, # comments and a leading "export " are
// allowed, and one pair of matching quotes around a value is removed. Nothing is expanded.
// Errors name the line number only, since a malformed line can be a key.
func parseEnvFile(data []byte) ([][2]string, error) {
	var out [][2]string
	seen := map[string]int{}
	for i, line := range strings.Split(string(data), "\n") {
		n, line := i+1, strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key = strings.TrimSpace(key)
		if !ok || !envKey.MatchString(key) {
			return nil, fmt.Errorf("line %d: want KEY=value", n)
		}
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("line %d: %s is already set on line %d", n, key, first)
		}
		seen[key] = n
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		out = append(out, [2]string{key, value})
	}
	return out, nil
}
