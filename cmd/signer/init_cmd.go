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
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
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

const defaultRPCURL = "https://mainnet.base.org"

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
		lookup:        os.LookupEnv,
		home:          os.UserHomeDir,
		goos:          runtime.GOOS,
		identity:      realIdentity,
		keychainWrite: keychainWriteSecurity,
	}
}

// runInit is `opensouk-signer init`: store the agent's private key, read with hidden input.
func runInit(ctx context.Context, args []string, d initDeps) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(d.errOut)
	agentFlag := fs.String("agent-id", "", "ERC-8004 agent id")
	chainFlag := fs.Int64("chain-id", 0, "chain id")
	rpcFlag := fs.String("rpc-url", "", "JSON-RPC URL")
	keychainFlag := fs.Bool("keychain", false, "store the key in the macOS Keychain")
	forceFlag := fs.Bool("force", false, "overwrite an existing key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keychainFlag && d.goos != "darwin" {
		fmt.Fprintln(d.errOut, "opensouk-signer init: --keychain is macOS only")
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
	hexKey, addr, err := parseAgentKey(raw)
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %v\n", err)
		return 1
	}
	fmt.Fprintf(d.errOut, "key for %s read\n", addr.Hex())

	agentStr := strings.TrimSpace(*agentFlag)
	if agentStr == "" {
		if agentStr, err = d.readLine("Agent ID (the # on your OpenSouk dashboard): "); err != nil {
			fmt.Fprintln(d.errOut, "opensouk-signer init: could not read the agent id")
			return 1
		}
		agentStr = strings.TrimSpace(agentStr)
	}
	agentID, ok := new(big.Int).SetString(agentStr, 10)
	if !ok || agentID.Sign() <= 0 {
		fmt.Fprintln(d.errOut, "opensouk-signer init: agent ID must be a positive whole number")
		return 2
	}

	chainID := *chainFlag
	if chainID == 0 {
		chainStr := defaultChainID
		if v, ok := d.lookup("CHAIN_ID"); ok && v != "" {
			chainStr = v
		}
		if chainID, err = strconv.ParseInt(chainStr, 10, 64); err != nil || chainID <= 0 {
			fmt.Fprintf(d.errOut, "opensouk-signer init: invalid chain id %q\n", chainStr)
			return 2
		}
	}
	rpcURL := *rpcFlag
	if rpcURL == "" {
		rpcURL = defaultRPCURL
		if v, ok := d.lookup("BASE_RPC_URL"); ok && v != "" {
			rpcURL = v
		}
	}

	owner, bound, err := d.identity(ctx, chainID, rpcURL, agentID)
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: could not check the identity on chain %d: %v\n", chainID, err)
		return 1
	}
	if addr != owner && (bound == (common.Address{}) || addr != bound) {
		fmt.Fprintf(d.errOut, "opensouk-signer init: key %s is neither the owner nor the bound wallet of agent %s (owner %s). Use the owner's key, or bind this wallet to the agent first with the sign_agent_wallet_set tool.\n", addr.Hex(), agentID, owner.Hex())
		return 1
	}

	if *keychainFlag {
		if err := d.keychainWrite(ctx, "AGENT_PRIVATE_KEY", hexKey); err != nil {
			fmt.Fprintf(d.errOut, "opensouk-signer init: could not write to the Keychain: %v\n", err)
			return 1
		}
		fmt.Fprintf(d.out, "stored AGENT_PRIVATE_KEY in the macOS Keychain (service %s)\n", keychainService)
		fmt.Fprintln(d.out, "restart your MCP client so the signer picks it up")
		return 0
	}

	path, err := envFilePath(d.lookup, d.home)
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %v\n", err)
		return 1
	}
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(d.errOut, "opensouk-signer init: could not read %s: %v\n", path, err)
		return 1
	}
	merged, err := mergeEnvKey(existing, "AGENT_PRIVATE_KEY", hexKey, *forceFlag)
	if errors.Is(err, errKeyExists) {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %s already holds a key; nothing changed. Re-run with --force to replace it.\n", path)
		return 1
	}
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %v\n", err)
		return 1
	}
	if err := writeEnvFileAtomic(path, merged); err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: could not write %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(d.out, "stored AGENT_PRIVATE_KEY in %s\n", path)
	fmt.Fprintln(d.out, "restart your MCP client so the signer picks it up")
	return 0
}

// realIdentity reads the agent's owner and bound wallet. The registry address resolves
// through env-driven helpers, so the chosen chain and RPC are exported for this process.
func realIdentity(ctx context.Context, chainID int64, rpcURL string, agentID *big.Int) (owner, bound common.Address, err error) {
	os.Setenv("CHAIN_ID", strconv.FormatInt(chainID, 10))
	os.Setenv("BASE_RPC_URL", rpcURL)
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return owner, bound, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()
	registry, err := resolveAddress(ctx, chainID, keyAgentRegistry)
	if err != nil {
		return owner, bound, err
	}
	if owner, err = readIdentityAddress(ctx, client, registry, "ownerOf", agentID); err != nil {
		return owner, bound, err
	}
	bound, err = readIdentityAddress(ctx, client, registry, "getAgentWallet", agentID)
	return owner, bound, err
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
