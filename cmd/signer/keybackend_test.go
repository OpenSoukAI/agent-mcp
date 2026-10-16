package main

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const testLocalKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func TestLocalSigner_SignDigestMatchesCryptoSign(t *testing.T) {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	s := newLocalSigner(key)
	if s.Address() != crypto.PubkeyToAddress(key.PublicKey) {
		t.Fatalf("address %s", s.Address().Hex())
	}
	digest := crypto.Keccak256Hash([]byte("ref-490"))
	got, err := s.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := crypto.Sign(digest[:], key)
	if string(got) != string(want) {
		t.Fatalf("local SignDigest differs from crypto.Sign:\n got %x\nwant %x", got, want)
	}
}

func TestLocalSigner_SignTypedDataSignsTheEIP712Hash(t *testing.T) {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	s := newLocalSigner(key)
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}},
			"Ping":         {{Name: "n", Type: "uint256"}},
		},
		PrimaryType: "Ping",
		Domain:      apitypes.TypedDataDomain{Name: "T", Version: "1", ChainId: math.NewHexOrDecimal256(84532), VerifyingContract: "0x0000000000000000000000000000000000000001"},
		Message:     apitypes.TypedDataMessage{"n": "7"},
	}
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SignTypedData(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := s.SignDigest(context.Background(), common.BytesToHash(hash))
	if string(got) != string(want) {
		t.Fatal("SignTypedData must sign exactly the EIP-712 hash of the typed data")
	}
}

func TestTransactOpts_SenderRecoversToSigner(t *testing.T) {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	s := newLocalSigner(key)
	chainID := big.NewInt(84532)
	opts := transactOpts(context.Background(), s, chainID)
	if opts.From != s.Address() {
		t.Fatalf("From %s, want %s", opts.From.Hex(), s.Address().Hex())
	}
	to := common.HexToAddress("0x0000000000000000000000000000000000000002")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000, To: &to, Value: big.NewInt(0)})
	signed, err := opts.Signer(opts.From, tx)
	if err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(chainID), signed)
	if err != nil || from != s.Address() {
		t.Fatalf("sender %s err %v, want %s", from.Hex(), err, s.Address().Hex())
	}
	if _, err := opts.Signer(common.HexToAddress("0x0000000000000000000000000000000000000009"), tx); err == nil {
		t.Fatal("signing for a different from-address must be refused")
	}
}

// TestNoRawKeyOutsideLocalAdapter: only keybackend.go may hold or use a raw private key, so a
// remote backend cannot be bypassed by a tool that signs on its own.
func TestNoRawKeyOutsideLocalAdapter(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "keybackend.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"crypto.Sign(", "NewKeyedTransactor", "ecdsa.PrivateKey", "crypto.HexToECDSA(", "crypto.ToECDSA", "crypto.GenerateKey(", "types.SignTx(", "types.SignNewTx("} {
			// providerauth.go holds the P-256 API credentials Turnkey and Privy authenticate
			// requests with. They cannot sign for a wallet; the secp256k1 bans still apply there.
			if f == "providerauth.go" && banned == "ecdsa.PrivateKey" {
				continue
			}
			if strings.Contains(string(b), banned) {
				t.Errorf("%s uses %s; sign through a Signer", f, banned)
			}
		}
	}
}
