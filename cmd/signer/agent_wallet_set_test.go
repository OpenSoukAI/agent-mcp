package main

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	awsTestRegistry = "0x1111111111111111111111111111111111111111"
	awsTestOwner    = "0x3333333333333333333333333333333333333333"
)

// TestAgentWalletSetTypeString_MatchesContract pins the type string to
// contracts/src/IdentityRegistryUpgradeable.sol AGENT_WALLET_SET_TYPEHASH.
func TestAgentWalletSetTypeString_MatchesContract(t *testing.T) {
	const want = "AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)"
	if agentWalletSetTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", agentWalletSetTypeString, want)
	}
}

// TestAgentWalletSetDigest_Vector checks the hand-rolled digest and the typed-data hash against
// a vector computed independently with cast (keccak/abi-encode of the domain and struct).
func TestAgentWalletSetDigest_Vector(t *testing.T) {
	const want = "190cdcd2297506b2f9388ec7d63ec7016b065f29ce6d2bd63d770aa94da707ab"
	m := agentWalletSetMessage{
		AgentID:   big.NewInt(7),
		NewWallet: common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Owner:     common.HexToAddress(awsTestOwner),
		Deadline:  big.NewInt(1893456000),
	}
	digest, err := computeAgentWalletSetDigest(m, 84532, common.HexToAddress(awsTestRegistry))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest) != want {
		t.Fatalf("digest %x, want %s", digest, want)
	}
	if _, err := signTyped(context.Background(), refuseSigner{}, agentWalletSetTypedData(m, 84532, common.HexToAddress(awsTestRegistry)), digest); !errors.Is(err, errRefuseSigner) {
		t.Fatalf("typed data hash must match the digest (then reach the signer), got %v", err)
	}
}

var errRefuseSigner = errors.New("reached the signer")

// refuseSigner fails every signature, so a test can tell "hash matched, signer reached" apart
// from a hash mismatch.
type refuseSigner struct{}

func (refuseSigner) Address() common.Address { return common.Address{} }
func (refuseSigner) SignDigest(context.Context, [32]byte) ([]byte, error) {
	return nil, errRefuseSigner
}
func (refuseSigner) SignTypedData(context.Context, apitypes.TypedData) ([]byte, error) {
	return nil, errRefuseSigner
}

// fakeIdentityChain answers ownerOf, getAgentWallet and the latest header.
type fakeIdentityChain struct {
	owner, wallet common.Address
	now           uint64
	ownerErr      error
	calls         []common.Address
}

func (f *fakeIdentityChain) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	f.calls = append(f.calls, *msg.To)
	method, err := identityRegistryABI.MethodById(msg.Data[:4])
	if err != nil {
		return nil, err
	}
	switch method.Name {
	case "ownerOf":
		if f.ownerErr != nil {
			return nil, f.ownerErr
		}
		return method.Outputs.Pack(f.owner)
	case "getAgentWallet":
		return method.Outputs.Pack(f.wallet)
	}
	return nil, errors.New("unexpected call " + method.Name)
}

func (f *fakeIdentityChain) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Time: f.now}, nil
}

func localTestSigner(t *testing.T) Signer {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return newLocalSigner(key)
}

func TestSignAgentWalletSet_SignsForTheWallet(t *testing.T) {
	s := localTestSigner(t)
	chain := &fakeIdentityChain{owner: common.HexToAddress(awsTestOwner), now: 1_800_000_000}
	registry := common.HexToAddress(awsTestRegistry)

	out, err := signAgentWalletSet(context.Background(), s, chain, 84532, registry, big.NewInt(7))
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.calls) == 0 || chain.calls[0] != registry {
		t.Fatalf("ownerOf must be read from the IdentityRegistry, calls %v", chain.calls)
	}
	if out.Deadline != "1800000300" {
		t.Fatalf("deadline %s, want chain time + 300", out.Deadline)
	}
	if out.NewWallet != s.Address().Hex() || out.Owner != common.HexToAddress(awsTestOwner).Hex() || out.AgentID != "7" ||
		out.IdentityRegistry != registry.Hex() {
		t.Fatalf("unexpected output %+v", out)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil || len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		t.Fatalf("want a 65-byte signature with v 27/28, got %s (%v)", out.Signature, err)
	}
	digest, err := computeAgentWalletSetDigest(agentWalletSetMessage{AgentID: big.NewInt(7), NewWallet: s.Address(),
		Owner: common.HexToAddress(awsTestOwner), Deadline: big.NewInt(1_800_000_300)}, 84532, registry)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] -= 27
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != s.Address() {
		t.Fatalf("signature does not recover to the wallet (%v)", err)
	}
	if !strings.Contains(out.Next, "setAgentWallet") || !strings.Contains(out.Next, out.Owner) {
		t.Fatalf("next must name the call and who sends it: %q", out.Next)
	}
}

func TestSignAgentWalletSet_RefusesTheOwnerKey(t *testing.T) {
	s := localTestSigner(t)
	chain := &fakeIdentityChain{owner: s.Address(), now: 1}
	_, err := signAgentWalletSet(context.Background(), s, chain, 84532, common.HexToAddress(awsTestRegistry), big.NewInt(7))
	if err == nil || !strings.Contains(err.Error(), "owns agent 7") {
		t.Fatalf("want a refusal for the owner's own key, got %v", err)
	}
}

func TestSignAgentWalletSet_RefusesWhenAlreadyBound(t *testing.T) {
	s := localTestSigner(t)
	chain := &fakeIdentityChain{owner: common.HexToAddress(awsTestOwner), wallet: s.Address(), now: 1}
	_, err := signAgentWalletSet(context.Background(), s, chain, 84532, common.HexToAddress(awsTestRegistry), big.NewInt(7))
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("want a refusal when the wallet is already bound, got %v", err)
	}
}

func TestSignAgentWalletSet_OwnerReadFailureRefuses(t *testing.T) {
	s := localTestSigner(t)
	chain := &fakeIdentityChain{ownerErr: errors.New("execution reverted"), now: 1}
	_, err := signAgentWalletSet(context.Background(), s, chain, 84532, common.HexToAddress(awsTestRegistry), big.NewInt(7))
	if err == nil || !strings.Contains(err.Error(), "ownerOf(7)") {
		t.Fatalf("want an ownerOf error naming the agent, got %v", err)
	}
}

func TestSignAgentWalletSet_InvalidAgentID(t *testing.T) {
	for _, id := range []string{"", "x", "-1"} {
		if _, err := parseAgentWalletSetInput(signAgentWalletSetInput{AgentID: id}); err == nil {
			t.Fatalf("agent_id %q must be refused", id)
		}
	}
}

// A prompt-injected agent must not bind this wallet to an identity it was not set up for: the
// owner of that identity could then claim this wallet's payments as its own receipts.
func TestHandleSignAgentWalletSet_RefusesTheFallbackKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	prev := signerKeys
	signerKeys = &keystore{keys: map[string]Signer{}, fallback: newLocalSigner(key)}
	t.Cleanup(func() { signerKeys = prev })
	t.Setenv("BASE_RPC_URL", "http://127.0.0.1:1") // never dialled: the refusal comes first

	_, _, err = handleSignAgentWalletSet(context.Background(), nil, signAgentWalletSetInput{AgentID: "7"})
	if err == nil || !strings.Contains(err.Error(), "agent 7") || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("want a refusal naming the agent and the fallback, got %v", err)
	}
}
