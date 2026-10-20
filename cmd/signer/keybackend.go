package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Signer is how every tool signs. No tool holds a key: the local adapter below is the only code
// that does, and a remote backend (kms.go) keeps the key out of this process entirely.
//
// Both methods return 65 bytes r||s||v with v in {0,1} and low-s, the crypto.Sign convention;
// callers that need 27/28 add 27 as before.
type Signer interface {
	Address() common.Address
	SignDigest(ctx context.Context, digest [32]byte) ([]byte, error)
	// SignTypedData exists so a policy backend can inspect the EIP-712 structure; a digest is
	// opaque to it. Local and KMS hash it with go-ethereum and sign the digest.
	SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error)
}

// TxSigner is implemented by a backend that must see the whole transaction: a policy engine
// checks its destination, which a signer hash hides. transactOpts prefers it over SignDigest.
type TxSigner interface {
	SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// MessageSigner signs an EIP-191 personal message, the provider applying the prefix, and returns
// r||s||v with v in {0,1}. agentAuthSignature prefers it over SignDigest of the prefixed hash.
type MessageSigner interface {
	SignPersonalMessage(ctx context.Context, msg []byte) ([]byte, error)
}

type localSigner struct{ key *ecdsa.PrivateKey }

func newLocalSigner(k *ecdsa.PrivateKey) *localSigner { return &localSigner{key: k} }

func (s *localSigner) Address() common.Address { return crypto.PubkeyToAddress(s.key.PublicKey) }

func (s *localSigner) SignDigest(_ context.Context, digest [32]byte) ([]byte, error) {
	return crypto.Sign(digest[:], s.key)
}

func (s *localSigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	return signTypedDataViaDigest(ctx, s, td)
}

// signTypedDataViaDigest is SignTypedData for a backend that only signs digests.
func signTypedDataViaDigest(ctx context.Context, s Signer, td apitypes.TypedData) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	return s.SignDigest(ctx, common.BytesToHash(hash))
}

// transactOpts signs transactions through s: whole, when s is a TxSigner, otherwise over the
// chain's EIP-155 signer hash.
func transactOpts(ctx context.Context, s Signer, chainID *big.Int) *bind.TransactOpts {
	from := s.Address()
	signer := types.LatestSignerForChainID(chainID)
	return &bind.TransactOpts{
		From:    from,
		Context: ctx,
		Signer: func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if addr != from {
				return nil, bind.ErrNotAuthorized
			}
			if ts, ok := s.(TxSigner); ok {
				return ts.SignTx(ctx, tx, chainID)
			}
			sig, err := s.SignDigest(ctx, signer.Hash(tx))
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, sig)
		},
	}
}

// keystore holds the signers resolved once at startup. agentID is the decimal string.
type keystore struct {
	keys     map[string]Signer
	fallback Signer
}

// parseKeystore parses AGENT_KEYS (comma-separated "agentId:0xkey") + the AGENT_PRIVATE_KEY
// fallback into local signers, validating every key at boot. Fails if no keys are configured or
// any entry is malformed.
func parseKeystore(agentKeys, agentPrivKey string) (*keystore, error) {
	ks := &keystore{keys: make(map[string]Signer)}
	if agentKeys != "" {
		for _, entry := range strings.Split(agentKeys, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			id, keyHex, ok := strings.Cut(entry, ":")
			if !ok {
				return nil, fmt.Errorf("AGENT_KEYS entry %q missing ':' (want agentId:0xkey)", entry)
			}
			id = strings.TrimSpace(id)
			if id == "" {
				return nil, fmt.Errorf("AGENT_KEYS entry %q has empty agentId", entry)
			}
			key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(keyHex), "0x"))
			if err != nil {
				return nil, fmt.Errorf("AGENT_KEYS agent %s: invalid key: %w", id, err)
			}
			if _, dup := ks.keys[id]; dup {
				return nil, fmt.Errorf("AGENT_KEYS duplicate agentId %s", id)
			}
			ks.keys[id] = newLocalSigner(key)
		}
	}
	if agentPrivKey != "" {
		key, err := crypto.HexToECDSA(strings.TrimPrefix(agentPrivKey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("AGENT_PRIVATE_KEY: invalid key: %w", err)
		}
		ks.fallback = newLocalSigner(key)
	}
	if len(ks.keys) == 0 && ks.fallback == nil {
		return nil, errors.New("no signing keys configured: set AGENT_KEYS or AGENT_PRIVATE_KEY in ~/.config/opensouk/signer.env, the macOS Keychain or the MCP client's config")
	}
	return ks, nil
}

// KeyFor returns the signer for agentID: exact match first, then the fallback.
func (ks *keystore) KeyFor(agentID string) (Signer, error) {
	if k, ok := ks.keys[agentID]; ok {
		return k, nil
	}
	if ks.fallback != nil {
		return ks.fallback, nil
	}
	return nil, fmt.Errorf("no key for agent %s and no fallback key: add it to AGENT_KEYS or set AGENT_PRIVATE_KEY (local), or add it or * to AGENT_WALLETS (kms)", agentID)
}

// signerKeys is initialized once in main() before the server starts.
var signerKeys *keystore
