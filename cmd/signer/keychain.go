package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// keychainService is the macOS Keychain service the signer's items live under, one generic
// password per setting, with the setting's name as the account.
const keychainService = "opensouk-signer"

// keychainSettings are the settings looked up in the Keychain: the secret ones.
var keychainSettings = []string{"AGENT_PRIVATE_KEY", "AGENT_KEYS", "TURNKEY_API_PRIVATE_KEY", "PRIVY_APP_SECRET", "PRIVY_AUTHORIZATION_KEY"}

var (
	securityPath = "/usr/bin/security"
	// keychainTimeout bounds one read. A read blocks while macOS shows an access dialog, and the
	// MCP client gives up on a signer that takes too long to start.
	keychainTimeout = 20 * time.Second
)

type keychainReader func(ctx context.Context, account string) (value string, found bool, err error)

// loadKeychain fills, on macOS only, each secret setting the MCP client and signer.env left
// without a value from the Keychain. A failed read is reported and ends the lookups rather than
// stopping the signer, so a Mac whose Keychain is locked (over SSH, say) still starts from its
// other settings. It returns lines for the boot log, which name settings and never values.
func loadKeychain(ctx context.Context, goos string, lookup func(string) (string, bool), setenv func(string, string) error, read keychainReader) ([]string, error) {
	if goos != "darwin" {
		return nil, nil
	}
	var loaded, overridden []string
	var report []string
	for _, k := range keychainSettings {
		v, found, err := read(ctx, k)
		if err != nil {
			report = append(report, fmt.Sprintf("Keychain skipped: %v", err))
			break
		}
		if !found {
			continue
		}
		if hasValue(lookup(k)) {
			overridden = append(overridden, k)
			continue
		}
		if err := setenv(k, v); err != nil {
			return nil, fmt.Errorf("set %s: %w", k, err)
		}
		loaded = append(loaded, k)
	}
	if len(loaded) > 0 {
		report = append([]string{"settings from the Keychain: " + strings.Join(loaded, ", ")}, report...)
	}
	for _, k := range overridden {
		report = append(report, fmt.Sprintf("%s is also in the Keychain; using the value from the MCP client's config or signer.env", k))
	}
	return report, nil
}

// securityRead reads one item with the security command. Exit status 44 is errSecItemNotFound.
func securityRead(ctx context.Context, account string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, keychainTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityPath, "find-generic-password", "-s", keychainService, "-a", account, "-w")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &stdout, &stderr, time.Second
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", false, fmt.Errorf("reading %s timed out after %s: macOS may be showing a Keychain access dialog", account, keychainTimeout)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading %s: %w: %s", account, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSuffix(stdout.String(), "\n"), true, nil
}
