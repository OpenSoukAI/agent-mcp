package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// configuredChainID is the chain this signer serves: CHAIN_ID, else defaultChainID.
func configuredChainID() (int64, error) {
	s := os.Getenv("CHAIN_ID")
	if s == "" {
		s = defaultChainID
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chain id %q: %w", s, err)
	}
	return id, nil
}

// protocolKey is a ProtocolAddressRegistry key label (keccak256 of the label on-chain).
type protocolKey string

const (
	keyReviewRegistry   protocolKey = "REVIEW_REGISTRY"
	keyEscrow           protocolKey = "ESCROW"
	keyMerchantRegistry protocolKey = "MERCHANT_REGISTRY"
	keyProductRegistry  protocolKey = "PRODUCT_REGISTRY"
	keySplitRouter      protocolKey = "SPLIT_ROUTER"
	keyAgentRegistry    protocolKey = "AGENT_REGISTRY" // the ERC-8004 IdentityRegistry
)

// envVar is the override variable for a key. ESCROW keeps its historical name.
func (k protocolKey) envVar() string {
	if k == keyEscrow {
		return "COMMISSION_ESCROW_ADDRESS"
	}
	return string(k) + "_ADDRESS"
}

// parByChain is the ProtocolAddressRegistry per chain this build knows. Base mainnet has no
// deployment yet. The testnet entry must equal the PAR the live backend reads, or every
// step-1 payload is refused on verifyingContract.
var parByChain = map[int64]common.Address{
	84532: common.HexToAddress("0xe6383d10EDb4c86F72d8327973d246680FFdDDdA"),
}

// addressFromEnv reads a 20-byte 0x address from envVar. Unset is (zero, false, nil); a value
// that is not a well-formed non-zero address is an error naming the variable, because
// common.HexToAddress would otherwise silently yield a zero or mis-padded address.
func addressFromEnv(envVar string) (common.Address, bool, error) {
	v := strings.TrimSpace(os.Getenv(envVar))
	if v == "" {
		return common.Address{}, false, nil
	}
	if !common.IsHexAddress(v) || common.HexToAddress(v) == (common.Address{}) {
		return common.Address{}, false, fmt.Errorf("%s=%q is not a 20-byte 0x address", envVar, v)
	}
	return common.HexToAddress(v), true, nil
}

// parAddressFor is PROTOCOL_ADDRESS_REGISTRY, else the baked entry for chainID.
func parAddressFor(chainID int64) (common.Address, error) {
	if a, set, err := addressFromEnv("PROTOCOL_ADDRESS_REGISTRY"); err != nil {
		return common.Address{}, err
	} else if set {
		return a, nil
	}
	if a, ok := parByChain[chainID]; ok {
		return a, nil
	}
	return common.Address{}, fmt.Errorf("chain %d has no built-in ProtocolAddressRegistry: set PROTOCOL_ADDRESS_REGISTRY, or set the contract address env vars directly", chainID)
}

var (
	addrCacheMu sync.Mutex
	addrCache   = map[string]common.Address{} // "<chainID>|<key>"
)

func resetAddressCache() {
	addrCacheMu.Lock()
	addrCache = map[string]common.Address{}
	addrCacheMu.Unlock()
}

// callPAR is the on-chain lookup, replaceable in tests.
var callPAR = parGetAddress

// resolveAddress returns the contract behind key on chainID: the env override if set, else
// the cached registry answer, else one registry read.
func resolveAddress(ctx context.Context, chainID int64, key protocolKey) (common.Address, error) {
	if a, set, err := addressFromEnv(key.envVar()); err != nil {
		return common.Address{}, err
	} else if set {
		return a, nil
	}
	cacheKey := strconv.FormatInt(chainID, 10) + "|" + string(key)
	addrCacheMu.Lock()
	cached, ok := addrCache[cacheKey]
	addrCacheMu.Unlock()
	if ok {
		return cached, nil
	}
	par, err := parAddressFor(chainID)
	if err != nil {
		return common.Address{}, fmt.Errorf("resolve %s: %w (or set %s)", key, err, key.envVar())
	}
	addr, err := callPAR(ctx, chainID, par, key)
	if err != nil {
		return common.Address{}, fmt.Errorf("resolve %s from ProtocolAddressRegistry %s on chain %d: %w", key, par.Hex(), chainID, err)
	}
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("ProtocolAddressRegistry %s on chain %d has no address for %s", par.Hex(), chainID, key)
	}
	addrCacheMu.Lock()
	addrCache[cacheKey] = addr
	addrCacheMu.Unlock()
	return addr, nil
}

var parABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(`[{"inputs":[{"name":"key","type":"bytes32"}],"name":"getAddress","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"}]`))
	if err != nil {
		panic(err)
	}
	return a
}()

// parGetAddress reads ProtocolAddressRegistry.getAddress(keccak256(key)) over BASE_RPC_URL.
func parGetAddress(ctx context.Context, chainID int64, par common.Address, key protocolKey) (common.Address, error) {
	client, _, err := dialChain(ctx, strconv.FormatInt(chainID, 10))
	if err != nil {
		return common.Address{}, err
	}
	defer client.Close()
	data, err := parABI.Pack("getAddress", crypto.Keccak256Hash([]byte(key)))
	if err != nil {
		return common.Address{}, err
	}
	out, err := client.CallContract(ctx, ethereum.CallMsg{To: &par, Data: data}, nil)
	if err != nil {
		return common.Address{}, fmt.Errorf("getAddress(%s): %w", key, err)
	}
	if len(out) == 0 {
		return common.Address{}, fmt.Errorf("no contract at ProtocolAddressRegistry %s on the chain BASE_RPC_URL serves (configured chain %d): set PROTOCOL_ADDRESS_REGISTRY to that chain's registry, or set %s", par.Hex(), chainID, key.envVar())
	}
	var addr common.Address
	if err := parABI.UnpackIntoInterface(&addr, "getAddress", out); err != nil {
		return common.Address{}, fmt.Errorf("decode getAddress(%s): %w", key, err)
	}
	return addr, nil
}

// defaultAttestationOrigin is where this build fetches /.well-known/opensouk per chain.
// Local stacks (anvil) set ATTESTATION_ORIGIN to their own backend.
var defaultAttestationOrigin = map[int64]string{
	8453:  "https://api.opensouk.ai",
	84532: "https://api.sysdev.wtf",
}

// attestationOrigin is the only origin pay_for_product fetches the manifest and product
// lookups from. A token on any other host is still verified against this origin's key.
func attestationOrigin(chainID int64) (string, error) {
	v := strings.TrimRight(strings.TrimSpace(os.Getenv("ATTESTATION_ORIGIN")), "/")
	if v == "" {
		d, ok := defaultAttestationOrigin[chainID]
		if !ok {
			return "", fmt.Errorf("chain %d has no built-in attestation origin: set ATTESTATION_ORIGIN to the OpenSouk API origin (scheme://host)", chainID)
		}
		return d, nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
		return "", fmt.Errorf("ATTESTATION_ORIGIN %q: want scheme://host with no path", v)
	}
	return v, nil
}

// warnAddressOverrides says, once at boot, which contract addresses are being overridden on a
// chain this build already knows. An override on a known chain is almost always a stale value.
func warnAddressOverrides(chainID int64, w io.Writer) {
	if _, known := parByChain[chainID]; !known {
		return
	}
	for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter, keyAgentRegistry} {
		if os.Getenv(k.envVar()) != "" {
			fmt.Fprintf(w, "opensouk-signer: %s overrides the ProtocolAddressRegistry value on chain %d; unset it unless you are testing\n", k.envVar(), chainID)
		}
	}
}
