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

// securityAddScript is the one command security -i reads on stdin. It never goes in argv,
// where ps would show the key.
func securityAddScript(account, value string) string {
	return "add-generic-password -U -s " + keychainService + " -a " + account + " -w " + value + "\n"
}

// keychainWriteSecurity stores value as the Keychain item for account. security's output is
// scrubbed of value before it reaches the error, in case the tool echoes its input.
func keychainWriteSecurity(ctx context.Context, account, value string) error {
	ctx, cancel := context.WithTimeout(ctx, keychainTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityPath, "-i")
	cmd.Stdin = strings.NewReader(securityAddScript(account, value))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &stdout, &stderr, time.Second
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("writing %s timed out after %s: macOS may be showing a Keychain access dialog", account, keychainTimeout)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String() + " " + stdout.String())
		detail = strings.ReplaceAll(detail, value, "[redacted]")
		return fmt.Errorf("writing %s: %v: %s", account, err, detail)
	}
	return nil
}
