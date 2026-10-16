package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// providerTypedDataJSON is td in the JSON shape a policy provider receives: types including
// EIP712Domain, chainId as a JSON number, and every hex value lowercase (Turnkey evaluates
// policies on lowercase hex). primaryKey is the provider's field name for the primary type.
func providerTypedDataJSON(td apitypes.TypedData, primaryKey string) (map[string]any, error) {
	fields, ok := td.Types[td.PrimaryType]
	if !ok {
		return nil, fmt.Errorf("typed data has no type for primary %s", td.PrimaryType)
	}
	if td.Domain.ChainId == nil {
		return nil, errors.New("typed data domain has no chainId")
	}
	types := make(map[string][]map[string]string, len(td.Types))
	for name, fs := range td.Types {
		out := make([]map[string]string, len(fs))
		for i, f := range fs {
			out[i] = map[string]string{"name": f.Name, "type": f.Type}
		}
		types[name] = out
	}
	msg := make(map[string]any, len(fields))
	for _, f := range fields {
		v, ok := td.Message[f.Name]
		if !ok {
			return nil, fmt.Errorf("typed data message has no %s", f.Name)
		}
		// Lowercase only hex-typed values: a string field (an intent's reason) is the user's text.
		if s, isStr := v.(string); isStr && (f.Type == "address" || strings.HasPrefix(f.Type, "bytes")) {
			v = strings.ToLower(s)
		}
		msg[f.Name] = v
	}
	chainID := (*big.Int)(td.Domain.ChainId)
	return map[string]any{
		"types":    types,
		primaryKey: td.PrimaryType,
		"domain": map[string]any{
			"name":              td.Domain.Name,
			"version":           td.Domain.Version,
			"chainId":           json.Number(chainID.String()),
			"verifyingContract": strings.ToLower(td.Domain.VerifyingContract),
		},
		"message": msg,
	}, nil
}
