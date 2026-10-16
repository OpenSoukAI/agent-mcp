package main

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// AWS KMS backend (SIGNER_BACKEND=kms): the key is an ECC_SECG_P256K1 KMS key and never enters
// this process. The DER/SPKI conversion is ported from the backend's internal/signing
// remote_signer.go (REF-414 spike), which proved it against SplitRouter on chain.

var (
	secp256k1N        = crypto.S256().Params().N
	secp256k1HalfN    = new(big.Int).Rsh(crypto.S256().Params().N, 1)
	oidECPublicKeyDER = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1DER   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// kmsCallTimeout bounds each KMS request: the SDK's default client has no overall deadline, so a
// stalled connection would hang the stdio server at boot or a tool call indefinitely.
var kmsCallTimeout = 15 * time.Second

type ecdsaDERSignature struct{ R, S *big.Int }

type spkiAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type subjectPublicKeyInfo struct {
	Algorithm spkiAlgorithmIdentifier
	PublicKey asn1.BitString
}

// addressFromSPKI derives the Ethereum address of a DER SubjectPublicKeyInfo (a KMS GetPublicKey
// response), refusing anything that is not a secp256k1 EC key.
func addressFromSPKI(spkiDER []byte) (common.Address, error) {
	var info subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(spkiDER, &info)
	if err != nil {
		return common.Address{}, fmt.Errorf("parse public key: %w", err)
	}
	if len(rest) != 0 {
		return common.Address{}, fmt.Errorf("parse public key: %d trailing bytes", len(rest))
	}
	if !info.Algorithm.Algorithm.Equal(oidECPublicKeyDER) {
		return common.Address{}, fmt.Errorf("public key algorithm is %s, want id-ecPublicKey", info.Algorithm.Algorithm)
	}
	if !info.Algorithm.Parameters.Equal(oidSecp256k1DER) {
		return common.Address{}, fmt.Errorf("key curve is %s, want secp256k1 (1.3.132.0.10): create the KMS key as ECC_SECG_P256K1", info.Algorithm.Parameters)
	}
	pub, err := crypto.UnmarshalPubkey(info.PublicKey.Bytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("parse public key point: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// ethSigFromDER converts a DER (r,s) over digest into r||s||v with v in {0,1} and low s. want is
// the address the signature must recover to: DER carries no recovery id, so it is found by trial.
func ethSigFromDER(derSig []byte, digest [32]byte, want common.Address) ([]byte, error) {
	var parsed ecdsaDERSignature
	rest, err := asn1.Unmarshal(derSig, &parsed)
	if err != nil {
		return nil, fmt.Errorf("parse DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parse DER signature: %d trailing bytes", len(rest))
	}
	return normaliseSig(parsed.R, parsed.S, digest, want)
}

// unexpandedRef matches a whole value that is still an environment reference, which a client
// passes through when it does not expand that syntax. The value is never printed: a ${VAR:-default}
// reference can carry a real key as its default.
var unexpandedRef = regexp.MustCompile(`^\$\{?(env:)?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}?$`)

// kmsAPI is the part of the AWS KMS client the signer uses.
type kmsAPI interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

type kmsSigner struct {
	api   kmsAPI
	keyID string
	addr  common.Address
}

func newKMSSigner(ctx context.Context, api kmsAPI, keyID string) (*kmsSigner, error) {
	ctx, cancel := context.WithTimeout(ctx, kmsCallTimeout)
	defer cancel()
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("KMS key %s: get public key: %w", keyID, err)
	}
	addr, err := addressFromSPKI(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("KMS key %s: %w", keyID, err)
	}
	return &kmsSigner{api: api, keyID: keyID, addr: addr}, nil
}

func (s *kmsSigner) Address() common.Address { return s.addr }

// SignDigest uses MessageType DIGEST, so KMS signs the 32 bytes as given (the keccak256 digest)
// despite the algorithm being named ECDSA_SHA_256.
func (s *kmsSigner) SignDigest(ctx context.Context, digest [32]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, kmsCallTimeout)
	defer cancel()
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	return ethSigFromDER(out.Signature, digest, s.addr)
}

func (s *kmsSigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	return signTypedDataViaDigest(ctx, s, td)
}

func defaultKMSClient(ctx context.Context) (kmsAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return kms.NewFromConfig(cfg), nil
}

// walletRefName is what an AGENT_WALLETS entry names, per backend, for error messages.
var walletRefName = map[string]string{"kms": "kmsKeyId", "turnkey": "walletAddress", "privy": "privyWalletId"}

// loadKeystore builds the keystore SIGNER_BACKEND selects. It returns, for a remote backend, one
// line per key naming the address it signs as, for the boot log.
func loadKeystore(ctx context.Context, getenv func(string) string, newKMS func(context.Context) (kmsAPI, error)) (*keystore, []string, error) {
	backend := strings.ToLower(strings.TrimSpace(getenv("SIGNER_BACKEND")))
	agentKeys, agentPriv, wallets := getenv("AGENT_KEYS"), getenv("AGENT_PRIVATE_KEY"), strings.TrimSpace(getenv("AGENT_WALLETS"))
	for name, v := range map[string]string{"AGENT_KEYS": agentKeys, "AGENT_PRIVATE_KEY": agentPriv, "AGENT_WALLETS": wallets} {
		if unexpandedRef.MatchString(strings.TrimSpace(v)) {
			return nil, nil, fmt.Errorf("%s is still an environment reference: the MCP client did not expand it. Export the variable in the shell that starts the client, or use that client's syntax (Claude Code ${VAR}, Cursor ${env:VAR}, Codex env_vars)", name)
		}
	}
	switch backend {
	case "", "local":
		if wallets != "" {
			return nil, nil, errors.New("AGENT_WALLETS is set but SIGNER_BACKEND is local: set SIGNER_BACKEND=kms, or remove AGENT_WALLETS")
		}
		ks, err := parseKeystore(agentKeys, agentPriv)
		return ks, nil, err
	case "kms", "turnkey", "privy":
		if agentKeys != "" || agentPriv != "" {
			return nil, nil, fmt.Errorf("SIGNER_BACKEND=%s takes keys from AGENT_WALLETS only: unset AGENT_KEYS and AGENT_PRIVATE_KEY so no raw key sits in this process", backend)
		}
		if wallets == "" {
			return nil, nil, fmt.Errorf("SIGNER_BACKEND=%s needs AGENT_WALLETS (comma-separated agentId:%s, '*' for the fallback)", backend, walletRefName[backend])
		}
		switch backend {
		case "turnkey":
			return turnkeyKeystore(ctx, getenv, wallets)
		case "privy":
			return nil, nil, errors.New("SIGNER_BACKEND=privy is not implemented yet")
		}
		api, err := newKMS(ctx)
		if err != nil {
			return nil, nil, err
		}
		return kmsKeystore(ctx, api, wallets)
	default:
		return nil, nil, fmt.Errorf("SIGNER_BACKEND %q is not supported: use local (default), kms, turnkey or privy", backend)
	}
}

func kmsKeystore(ctx context.Context, api kmsAPI, wallets string) (*keystore, []string, error) {
	return walletKeystore(ctx, wallets, "KMS key", func(ctx context.Context, ref string) (Signer, error) {
		return newKMSSigner(ctx, api, ref)
	})
}
