package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// errRawDigestRefused is what a policy backend returns from SignDigest. On Turnkey and Privy a
// raw-hash signature can be any EIP-712 or transaction signature, so serving one would make the
// provider's policy meaningless.
var errRawDigestRefused = errors.New("this signer backend does not sign raw digests: a policy engine cannot inspect a hash, so allowing one would let it sign anything")

// normaliseSig turns (r, s) over digest into r||s||v with v in {0,1} and low s, finding v by
// trial. want is the address the signature must recover to.
func normaliseSig(r, s *big.Int, digest [32]byte, want common.Address) ([]byte, error) {
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(secp256k1N) >= 0 || s.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("signature r or s out of range")
	}
	// Providers do not promise low s; OZ's ECDSA reverts on the high variant.
	if s.Cmp(secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(secp256k1N, s)
	}
	sig := make([]byte, 65)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	for _, v := range []byte{0, 1} {
		sig[64] = v
		if pub, err := crypto.SigToPub(digest[:], sig); err == nil && crypto.PubkeyToAddress(*pub) == want {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("no recovery id yields %s: the signature is over a different digest or from a different key", want.Hex())
}

// checkSig65 normalises a 65-byte r||s||v signature from a provider (v in 0/1 or 27/28) and
// checks it recovers to want.
func checkSig65(sig []byte, digest [32]byte, want common.Address) ([]byte, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("signature is %d bytes, want 65", len(sig))
	}
	return normaliseSig(new(big.Int).SetBytes(sig[0:32]), new(big.Int).SetBytes(sig[32:64]), digest, want)
}

// walletRef is one AGENT_WALLETS entry: an agent id ("*" for the fallback) and the backend's
// reference for its key (a KMS key id, a Turnkey address, a Privy wallet id).
type walletRef struct{ agentID, ref string }

// parseWalletList parses AGENT_WALLETS, comma-separated agentId:ref.
func parseWalletList(wallets string) ([]walletRef, error) {
	var out []walletRef
	seen := map[string]bool{}
	for _, entry := range strings.Split(wallets, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Split on the first colon only: a KMS key ARN contains colons of its own.
		id, ref, _ := strings.Cut(entry, ":")
		id, ref = strings.TrimSpace(id), strings.TrimSpace(ref)
		if ref == "" {
			return nil, fmt.Errorf("AGENT_WALLETS entry %q has no key id (want agentId:keyRef)", entry)
		}
		if id != "*" {
			// Canonical form only: tools look keys up by exact string, so "007" would never match
			// agent 7 and every call would silently sign with the * key.
			if n, ok := new(big.Int).SetString(id, 10); !ok || n.Sign() < 0 || n.String() != id {
				return nil, fmt.Errorf("AGENT_WALLETS entry %q: agent id must be a decimal number without sign or leading zeros, or *", entry)
			}
		}
		if seen[id] {
			return nil, fmt.Errorf("AGENT_WALLETS duplicate agent id %s", id)
		}
		seen[id] = true
		out = append(out, walletRef{id, ref})
	}
	if len(out) == 0 {
		return nil, errors.New("AGENT_WALLETS has no entries")
	}
	return out, nil
}

// walletKeystore opens one Signer per AGENT_WALLETS entry. kind names the reference in the boot
// report ("KMS key", "Turnkey wallet", ...).
func walletKeystore(ctx context.Context, wallets, kind string, open func(context.Context, string) (Signer, error)) (*keystore, []string, error) {
	refs, err := parseWalletList(wallets)
	if err != nil {
		return nil, nil, err
	}
	ks := &keystore{keys: make(map[string]Signer)}
	var report []string
	for _, w := range refs {
		s, err := open(ctx, w.ref)
		if err != nil {
			return nil, nil, err
		}
		if w.agentID == "*" {
			ks.fallback = s
		} else {
			ks.keys[w.agentID] = s
		}
		report = append(report, fmt.Sprintf("agent %s signs as %s (%s %s)", w.agentID, s.Address().Hex(), kind, w.ref))
	}
	return ks, report, nil
}
