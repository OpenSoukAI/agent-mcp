package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/term"
)

type initDeps struct {
	out, errOut   io.Writer
	isTerminal    func() bool
	readSecret    func(prompt string) (string, error)
	readLine      func(prompt string) (string, error)
	lookup        func(string) (string, bool)
	home          func() (string, error)
	goos          string
	identity      func(ctx context.Context, chainID int64, rpcURL string, agentID *big.Int) (owner, bound common.Address, err error)
	keychainWrite func(ctx context.Context, account, value string) error
}

var errNotYetAvailable = errors.New("not yet available")

func defaultInitDeps() initDeps {
	stdin := bufio.NewReader(os.Stdin)
	return initDeps{
		out:        os.Stdout,
		errOut:     os.Stderr,
		isTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		readSecret: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		},
		readLine: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			s, err := stdin.ReadString('\n')
			if err != nil && (!errors.Is(err, io.EOF) || s == "") {
				return "", err
			}
			return strings.TrimSpace(s), nil
		},
		lookup: os.LookupEnv,
		home:   os.UserHomeDir,
		goos:   runtime.GOOS,
		identity: func(context.Context, int64, string, *big.Int) (common.Address, common.Address, error) {
			return common.Address{}, common.Address{}, errNotYetAvailable
		},
		keychainWrite: func(context.Context, string, string) error { return errNotYetAvailable },
	}
}

// runInit is `opensouk-signer init`: store the agent's private key, read with hidden input.
func runInit(ctx context.Context, args []string, d initDeps) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(d.errOut)
	fs.String("agent-id", "", "ERC-8004 agent id")
	fs.Int64("chain-id", 0, "chain id")
	fs.String("rpc-url", "", "JSON-RPC URL")
	fs.Bool("keychain", false, "store the key in the macOS Keychain")
	fs.Bool("force", false, "overwrite an existing key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !d.isTerminal() {
		fmt.Fprintln(d.errOut, "opensouk-signer init: stdin is not a terminal; run this in your own terminal")
		return 2
	}
	raw, err := d.readSecret("Private key of the account that owns your agent (input hidden): ")
	if err != nil {
		fmt.Fprintln(d.errOut, "opensouk-signer init: could not read the key")
		return 1
	}
	_, addr, err := parseAgentKey(raw)
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %v\n", err)
		return 1
	}
	fmt.Fprintf(d.errOut, "key for %s read\n", addr.Hex())
	fmt.Fprintln(d.errOut, "opensouk-signer init: not implemented yet")
	return 1
}

var (
	errSeedPhrase = errors.New("that looks like a seed phrase. init takes one account's private key: export it from your wallet app (account details → show private key)")
	errNotAKey    = errors.New("not a private key: want 64 hex characters, with or without 0x")
)

// parseAgentKey errors never include the input.
func parseAgentKey(s string) (hexKey string, addr common.Address, err error) {
	s = strings.TrimSpace(s)
	if words := strings.Fields(s); len(words) >= 12 && isLowerWords(words) {
		return "", common.Address{}, errSeedPhrase
	}
	h := strings.ToLower(s)
	h = strings.TrimPrefix(h, "0x")
	if len(h) != 64 {
		return "", common.Address{}, errNotAKey
	}
	ls, kerr := newLocalSignerFromHex(h)
	if kerr != nil {
		return "", common.Address{}, errNotAKey
	}
	return "0x" + h, ls.Address(), nil
}

func isLowerWords(words []string) bool {
	for _, w := range words {
		for _, r := range w {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}

// dispatchEarly runs subcommands that must not load the env file or Keychain first.
func dispatchEarly(args []string) (handled bool, code int) {
	if len(args) > 1 && args[1] == "init" {
		return true, runInit(context.Background(), args[2:], defaultInitDeps())
	}
	return false, 0
}
