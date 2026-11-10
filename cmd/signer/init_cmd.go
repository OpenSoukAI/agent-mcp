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
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	keychainRead  func(ctx context.Context, account string) (value string, found bool, err error)
}

const defaultRPCURL = "https://mainnet.base.org"

var (
	initChainTimeout = 30 * time.Second
	keyLikeArg       = regexp.MustCompile(`^(--?[A-Za-z-]+=)?(0[xX])?[0-9a-fA-F]{64}$`)
)

func sepoliaHint(chainID int64) string {
	if chainID == 84532 {
		return ""
	}
	return " If your agent is on Base Sepolia, add --chain-id 84532 --rpc-url https://sepolia.base.org."
}

// warnAgentKeys flags an AGENT_KEYS entry for agentID in the env file: the signer picks it over
// AGENT_PRIVATE_KEY for that agent.
func warnAgentKeys(d initDeps, path string, entries [][2]string, agentID *big.Int) {
	for _, e := range entries {
		if e[0] != "AGENT_KEYS" {
			continue
		}
		for _, entry := range strings.Split(e[1], ",") {
			if id, _, ok := strings.Cut(entry, ":"); ok && strings.TrimSpace(id) == agentID.String() {
				fmt.Fprintf(d.errOut, "opensouk-signer init: warning: AGENT_KEYS in %s has an entry for agent %s; the signer uses that entry, not AGENT_PRIVATE_KEY, for this agent\n", path, agentID)
				return
			}
		}
	}
}

func defaultInitDeps() initDeps {
	stdin := bufio.NewReader(os.Stdin)
	return initDeps{
		out:        os.Stdout,
		errOut:     os.Stderr,
		isTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		readSecret: func(prompt string) (string, error) {
			fd := int(os.Stdin.Fd())
			state, err := term.GetState(fd)
			if err != nil {
				return "", err
			}
			// Ctrl-C during ReadPassword would otherwise exit with echo still off.
			sigs := make(chan os.Signal, 1)
			done := make(chan struct{})
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
			go func() {
				select {
				case <-sigs:
					term.Restore(fd, state)
					fmt.Fprintln(os.Stderr)
					os.Exit(130)
				case <-done:
				}
			}()
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(fd)
			signal.Stop(sigs)
			close(done)
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
		keychainRead:  securityRead,
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
	fs.Usage = func() {
		fmt.Fprintln(d.errOut, "usage: opensouk-signer init [--agent-id N] [--chain-id N] [--rpc-url URL] [--keychain] [--force]")
		fmt.Fprintln(d.errOut, "The private key is asked for with hidden input; never pass it as an argument.")
		fs.PrintDefaults()
	}
	for _, a := range args {
		if keyLikeArg.MatchString(a) {
			fmt.Fprintln(d.errOut, "opensouk-signer init: never put the key on the command line; it is now in your shell history — move the funds to a new key if that history is shared. Run init without it and paste the key at the hidden prompt.")
			return 2
		}
	}
	// The flag package's own errors echo the offending argument; the key-shaped ones are refused above.
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(d.errOut, "opensouk-signer init: init takes only flags; see opensouk-signer init --help")
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
	var (
		path           string
		existing       []byte
		entries        [][2]string
		envPlaceholder bool
	)
	if *keychainFlag {
		var ok bool
		if path, existing, entries, ok = readInitEnvFile(d); !ok {
			return 1
		}
		for _, e := range entries {
			if e[0] != "AGENT_PRIVATE_KEY" {
				continue
			}
			if e[1] == "" || e[1] == keyPlaceholder {
				envPlaceholder = true
			} else if hasValue(e[1], true) {
				fmt.Fprintf(d.errOut, "opensouk-signer init: %s sets AGENT_PRIVATE_KEY, which would override the Keychain; nothing changed. Remove that line from the file, or run init without --keychain to store the key in the file.\n", path)
				return 1
			}
		}
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

	idCtx, cancel := context.WithTimeout(ctx, initChainTimeout)
	owner, bound, err := d.identity(idCtx, chainID, rpcURL, agentID)
	cancel()
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: could not check the identity on chain %d: %v (RPC %s).%s\n", chainID, err, rpcURL, sepoliaHint(chainID))
		return 1
	}
	if addr != owner && (bound == (common.Address{}) || addr != bound) {
		fmt.Fprintf(d.errOut, "opensouk-signer init: key %s is neither the owner nor the bound wallet of agent %s on chain %d (owner %s, read from %s). Use the owner's key, or bind this wallet to the agent first with the sign_agent_wallet_set tool.%s\n", addr.Hex(), agentID, chainID, owner.Hex(), rpcURL, sepoliaHint(chainID))
		return 1
	}

	if *keychainFlag {
		if !*forceFlag {
			cur, found, err := d.keychainRead(ctx, "AGENT_PRIVATE_KEY")
			if err != nil {
				fmt.Fprintf(d.errOut, "opensouk-signer init: could not check the Keychain: %v\n", err)
				return 1
			}
			if found && cur != "" && cur != keyPlaceholder {
				fmt.Fprintf(d.errOut, "opensouk-signer init: the Keychain (service %s) already holds a key; nothing changed. Re-run with --force to replace it.\n", keychainService)
				return 1
			}
		}
		if err := d.keychainWrite(ctx, "AGENT_PRIVATE_KEY", hexKey); err != nil {
			fmt.Fprintf(d.errOut, "opensouk-signer init: could not write to the Keychain: %v\n", err)
			return 1
		}
		got, found, err := d.keychainRead(ctx, "AGENT_PRIVATE_KEY")
		if err != nil {
			fmt.Fprintf(d.errOut, "opensouk-signer init: the Keychain did not store the key: %v\n", err)
			return 1
		}
		if !found || got != hexKey {
			fmt.Fprintln(d.errOut, "opensouk-signer init: the Keychain did not store the key")
			return 1
		}
		if envPlaceholder {
			if err := removeEnvLine(path, existing); err != nil {
				fmt.Fprintf(d.errOut, "opensouk-signer init: warning: could not remove the empty AGENT_PRIVATE_KEY line from %s: %v\n", path, err)
			}
		}
		fmt.Fprintf(d.out, "stored AGENT_PRIVATE_KEY in the macOS Keychain (service %s)\n", keychainService)
		warnAgentKeys(d, path, entries, agentID)
		fmt.Fprintln(d.out, "restart your MCP client so the signer picks it up")
		return 0
	}

	if path, existing, entries, ok = readInitEnvFile(d); !ok {
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
	warnAgentKeys(d, path, entries, agentID)
	fmt.Fprintln(d.out, "restart your MCP client so the signer picks it up")
	return 0
}

// readInitEnvFile reads the env file init writes to; a missing file reads as empty. On failure it
// has already reported the error.
func readInitEnvFile(d initDeps) (path string, data []byte, entries [][2]string, ok bool) {
	path, err := envFilePath(d.lookup, d.home)
	if err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %v\n", err)
		return "", nil, nil, false
	}
	data, err = os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(d.errOut, "opensouk-signer init: could not read %s: %v\n", path, err)
		return "", nil, nil, false
	}
	if entries, err = parseEnvFile(data); err != nil {
		fmt.Fprintf(d.errOut, "opensouk-signer init: %s: %v\n", path, err)
		return "", nil, nil, false
	}
	return path, data, entries, true
}

func removeEnvLine(path string, existing []byte) error {
	trimmed, removed, err := removeEnvKey(existing, "AGENT_PRIVATE_KEY")
	if err != nil || !removed {
		return err
	}
	return writeEnvFileAtomic(path, trimmed)
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
