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
	fmt.Fprintln(d.errOut, "opensouk-signer init: not implemented yet")
	return 1
}

// dispatchEarly runs subcommands that must not load the env file or Keychain first.
func dispatchEarly(args []string) (handled bool, code int) {
	if len(args) > 1 && args[1] == "init" {
		return true, runInit(context.Background(), args[2:], defaultInitDeps())
	}
	return false, 0
}
