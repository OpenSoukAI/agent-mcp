package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// unsignedTxRLP is the unsigned encoding of tx whose keccak256 is the EIP-155 / EIP-1559
// signer hash: what a provider's sign-transaction endpoint parses and signs.
func unsignedTxRLP(tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	switch tx.Type() {
	case types.DynamicFeeTxType:
		body, err := rlp.EncodeToBytes([]any{chainID, tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList()})
		if err != nil {
			return nil, err
		}
		return append([]byte{types.DynamicFeeTxType}, body...), nil
	case types.LegacyTxType:
		return rlp.EncodeToBytes([]any{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), chainID, uint(0), uint(0)})
	default:
		return nil, fmt.Errorf("transaction type %d is not supported by remote signing", tx.Type())
	}
}

// attachProviderSig takes a provider's signed transaction, keeps only its (r, s), and attaches
// them to want after checking they recover to from over want's own signer hash. A provider that
// signed different fields than requested therefore fails recovery instead of slipping through.
func attachProviderSig(signed []byte, want *types.Transaction, chainID *big.Int, from common.Address) (*types.Transaction, error) {
	var got types.Transaction
	if err := got.UnmarshalBinary(signed); err != nil {
		return nil, fmt.Errorf("decode provider-signed transaction: %w", err)
	}
	signer := types.LatestSignerForChainID(chainID)
	if signer.Hash(&got) != signer.Hash(want) {
		return nil, fmt.Errorf("the provider signed a different transaction than requested (hash %s, want %s)", signer.Hash(&got).Hex(), signer.Hash(want).Hex())
	}
	_, r, s := got.RawSignatureValues()
	sig, err := normaliseSig(r, s, signer.Hash(want), from)
	if err != nil {
		return nil, fmt.Errorf("provider-signed transaction: %w", err)
	}
	return want.WithSignature(signer, sig)
}
