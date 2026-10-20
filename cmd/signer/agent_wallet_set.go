package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── sign_agent_wallet_set ───────────────────────────────────────────────────────
//
// IdentityRegistry.setAgentWallet binds a second wallet to an identity. The owner sends it, but
// the NEW wallet must sign AgentWalletSet first, so a provider wallet (KMS, Turnkey, Privy) that
// only this signer can use needs this tool to be bound. The signature only consents to being
// bound: it recovers to this wallet and is useless for any other address.

// Must match contracts/src/IdentityRegistryUpgradeable.sol AGENT_WALLET_SET_TYPEHASH.
const agentWalletSetTypeString = "AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)"

var agentWalletSetTypehash = crypto.Keccak256Hash([]byte(agentWalletSetTypeString))

// agentWalletSetWindow is the contract's MAX_DEADLINE_DELAY: the deadline may be at most this far
// past block.timestamp when setAgentWallet runs.
const agentWalletSetWindow = 300

var identityRegistryABI = mustParseABI(`[
	{"type":"function","name":"ownerOf","stateMutability":"view","inputs":[{"name":"tokenId","type":"uint256"}],"outputs":[{"name":"","type":"address"}]},
	{"type":"function","name":"getAgentWallet","stateMutability":"view","inputs":[{"name":"agentId","type":"uint256"}],"outputs":[{"name":"","type":"address"}]}
]`)

type signAgentWalletSetInput struct {
	AgentID string `json:"agent_id"` // decimal; the identity to bind this signer's wallet to
}

type signAgentWalletSetOutput struct {
	Signature        string `json:"signature"`         // 0x, 65 bytes; the setAgentWallet signature argument
	AgentID          string `json:"agent_id"`          // echoed
	NewWallet        string `json:"new_wallet"`        // this signer's wallet for agent_id
	Owner            string `json:"owner"`             // ownerOf(agent_id): the only sender setAgentWallet accepts
	Deadline         string `json:"deadline"`          // unix seconds; setAgentWallet must be mined by then
	IdentityRegistry string `json:"identity_registry"` // the contract to send it to
	Next             string `json:"next"`
}

type agentWalletSetMessage struct {
	AgentID   *big.Int
	NewWallet common.Address
	Owner     common.Address
	Deadline  *big.Int
}

// identityChain is what signAgentWalletSet reads from the chain, so it is testable without one.
type identityChain interface {
	contractCaller
	headerReader
}

func parseAgentWalletSetInput(in signAgentWalletSetInput) (*big.Int, error) {
	id, ok := new(big.Int).SetString(strings.TrimSpace(in.AgentID), 10)
	if !ok || id.Sign() < 0 {
		return nil, fmt.Errorf("invalid agent_id: %q (want a decimal string)", in.AgentID)
	}
	return id, nil
}

func computeAgentWalletSetDigest(m agentWalletSetMessage, chainID int64, registry common.Address) ([]byte, error) {
	domainPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(specAgentWalletSet.name)),
		crypto.Keccak256Hash([]byte(specAgentWalletSet.version)),
		big.NewInt(chainID),
		registry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiUint256}, {Type: abiAddress}, {Type: abiAddress}, {Type: abiUint256},
	}.Pack(agentWalletSetTypehash, m.AgentID, m.NewWallet, m.Owner, m.Deadline)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func agentWalletSetTypedData(m agentWalletSetMessage, chainID int64, registry common.Address) apitypes.TypedData {
	return typedData(specAgentWalletSet.primary, specAgentWalletSet.name, specAgentWalletSet.version, big.NewInt(chainID), registry.Hex(), []tdField{
		{"agentId", "uint256", m.AgentID.String()},
		{"newWallet", "address", m.NewWallet.Hex()},
		{"owner", "address", m.Owner.Hex()},
		{"deadline", "uint256", m.Deadline.String()},
	})
}

func readIdentityAddress(ctx context.Context, c contractCaller, registry common.Address, method string, agentID *big.Int) (common.Address, error) {
	data, err := identityRegistryABI.Pack(method, agentID)
	if err != nil {
		return common.Address{}, err
	}
	out, err := c.CallContract(ctx, ethereum.CallMsg{To: &registry, Data: data}, nil)
	if err != nil {
		return common.Address{}, fmt.Errorf("%s(%s) on IdentityRegistry %s: %w", method, agentID, registry.Hex(), err)
	}
	var addr common.Address
	if err := identityRegistryABI.UnpackIntoInterface(&addr, method, out); err != nil {
		return common.Address{}, fmt.Errorf("decode %s(%s): %w", method, agentID, err)
	}
	return addr, nil
}

func signAgentWalletSet(ctx context.Context, s Signer, chain identityChain, chainID int64, registry common.Address, agentID *big.Int) (signAgentWalletSetOutput, error) {
	wallet := s.Address()
	owner, err := readIdentityAddress(ctx, chain, registry, "ownerOf", agentID)
	if err != nil {
		return signAgentWalletSetOutput{}, err
	}
	if owner == wallet {
		return signAgentWalletSetOutput{}, fmt.Errorf("this signer's wallet %s owns agent %s already: there is nothing to bind", wallet.Hex(), agentID)
	}
	bound, err := readIdentityAddress(ctx, chain, registry, "getAgentWallet", agentID)
	if err != nil {
		return signAgentWalletSetOutput{}, err
	}
	if bound == wallet {
		return signAgentWalletSetOutput{}, fmt.Errorf("wallet %s is already the agent wallet of agent %s", wallet.Hex(), agentID)
	}
	now, err := chainNow(ctx, chain)
	if err != nil {
		return signAgentWalletSetOutput{}, err
	}

	m := agentWalletSetMessage{AgentID: agentID, NewWallet: wallet, Owner: owner, Deadline: big.NewInt(now + agentWalletSetWindow)}
	digest, err := computeAgentWalletSetDigest(m, chainID, registry)
	if err != nil {
		return signAgentWalletSetOutput{}, fmt.Errorf("compute digest: %w", err)
	}
	sig, err := signTyped(ctx, s, agentWalletSetTypedData(m, chainID, registry), digest)
	if err != nil {
		return signAgentWalletSetOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1

	return signAgentWalletSetOutput{
		Signature:        "0x" + hex.EncodeToString(sig),
		AgentID:          agentID.String(),
		NewWallet:        wallet.Hex(),
		Owner:            owner.Hex(),
		Deadline:         m.Deadline.String(),
		IdentityRegistry: registry.Hex(),
		Next: fmt.Sprintf("The owner %s must send setAgentWallet(%s, %s, %s, signature) to %s before the deadline (about %d seconds from now). This signer cannot send it.",
			owner.Hex(), agentID, wallet.Hex(), m.Deadline, registry.Hex(), agentWalletSetWindow),
	}, nil
}

func handleSignAgentWalletSet(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in signAgentWalletSetInput,
) (*sdkmcp.CallToolResult, signAgentWalletSetOutput, error) {
	agentID, err := parseAgentWalletSetInput(in)
	if err != nil {
		return nil, signAgentWalletSetOutput{}, err
	}
	// Not the fallback: bound to an identity it was not set up for, this wallet's payments would
	// count as that identity's receipts.
	keySigner, err := signerKeys.ExactKeyFor(agentID.String())
	if err != nil {
		return nil, signAgentWalletSetOutput{}, err
	}
	client, chainID, err := dialChain(ctx, "")
	if err != nil {
		return nil, signAgentWalletSetOutput{}, err
	}
	defer client.Close()
	registry, err := resolveAddress(ctx, chainID, keyAgentRegistry)
	if err != nil {
		return nil, signAgentWalletSetOutput{}, err
	}
	out, err := signAgentWalletSet(ctx, keySigner, client, chainID, registry, agentID)
	return nil, out, err
}
