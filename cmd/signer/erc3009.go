package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
	batchsettlement "github.com/x402-foundation/x402/go/mechanisms/evm/batch-settlement"
)

// erc3009ReceiveAuthorizationType is the EIP-712 primary type SplitRouter.route() requires.
//
// ERC-3009 defines TransferWithAuthorization and ReceiveWithAuthorization with identical fields
// and different struct names, so they hash to different EIP-712 digests and are not
// interchangeable. route() calls receiveWithAuthorization, which real Circle USDC validates
// against the Receive typehash; a Transfer signature is rejected inside the token (REF-269).
//
// Kept in lockstep with the backend's signing.ERC3009ReceiveAuthorizationType. The backend
// rejects a wrong-typehash payload with requiredAuthorizationType naming the type it wants, so a
// divergence here surfaces as a named rejection rather than a silent revert.
const erc3009ReceiveAuthorizationType = "ReceiveWithAuthorization"

// hashERC3009Receive computes the digest the buyer key signs for an x402 purchase.
//
// Uses the upstream Receive type table rather than hand-rolling the struct hash. It lives in the
// batch-settlement subpackage; the exact/EVM scheme's own hasher (evm.HashEIP3009Authorization)
// pins TransferWithAuthorization inline and offers no way to select the other type.
func hashERC3009Receive(
	auth evm.ExactEIP3009Authorization,
	chainID *big.Int,
	tokenAddr string,
	tokenName string,
	tokenVersion string,
) ([]byte, error) {
	value, ok := new(big.Int).SetString(auth.Value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid authorization value %q", auth.Value)
	}
	validAfter, ok := new(big.Int).SetString(auth.ValidAfter, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validAfter %q", auth.ValidAfter)
	}
	validBefore, ok := new(big.Int).SetString(auth.ValidBefore, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validBefore %q", auth.ValidBefore)
	}
	nonceBytes, err := evm.HexToBytes(auth.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	return evm.HashTypedData(
		evm.TypedDataDomain{
			Name:              tokenName,
			Version:           tokenVersion,
			ChainID:           chainID,
			VerifyingContract: tokenAddr,
		},
		batchsettlement.ReceiveAuthorizationTypes,
		erc3009ReceiveAuthorizationType,
		map[string]interface{}{
			"from":        common.HexToAddress(auth.From).Hex(),
			"to":          common.HexToAddress(auth.To).Hex(),
			"value":       value,
			"validAfter":  validAfter,
			"validBefore": validBefore,
			"nonce":       nonceBytes,
		},
	)
}
