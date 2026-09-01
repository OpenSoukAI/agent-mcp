package main

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// ── Custom-error revert decoding ────────────────────────────────────────────────
//
// Every tool that sends a transaction wants the same thing from a failed estimate or
// send: turn the contract's 4-byte custom-error selector into a sentence the calling
// agent can act on. The MECHANISM is shared here; the MESSAGES are not.
//
// Each tool keeps its own table in its own file, deliberately. The same contract error
// means different things to different callers — CommissionEscrow's `AlreadySettled` is
// "too late to bind" to bind_escrow and "the oracle got there first, nothing is stuck"
// to trigger_settle_fallback, and `EscrowNotFound` reads differently again. Folding
// these into one per-contract table would replace advice with a lookup.

// dataError is the interface go-ethereum's RPC errors implement to expose revert data.
type dataError interface{ ErrorData() interface{} }

// revertTable maps a custom-error selector (4 bytes, lowercase hex, no 0x) to a
// caller-facing explanation. Build one with newRevertTable.
type revertTable map[string]string

// newRevertTable keys a signature→message map by each signature's 4-byte selector.
// Selectors are derived here rather than hand-copied, so there is no hex to drift out of
// sync with the contract, and they are computed ONCE (callers hold the result in a
// package var) rather than on every decode.
func newRevertTable(bySignature map[string]string) revertTable {
	t := make(revertTable, len(bySignature))
	for sig, msg := range bySignature {
		t[hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4])] = msg
	}
	return t
}

// lookupData maps raw revert data to this table's explanation. Only the leading selector
// is matched; any ABI-encoded error arguments after it are ignored.
func (t revertTable) lookupData(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	msg, ok := t[hex.EncodeToString(data[:4])]
	return msg, ok
}

// lookupErr extracts revert data from a go-ethereum tx/estimate/call error and maps its
// selector to this table's explanation. Returns ("", false) when the error carries no
// revert data or the selector is not in this table — callers fall back to wrapping the
// raw error, so an unrecognised revert is never swallowed.
func (t revertTable) lookupErr(err error) (string, bool) {
	var de dataError
	if !errors.As(err, &de) {
		return "", false
	}
	hexData, ok := de.ErrorData().(string)
	if !ok {
		return "", false
	}
	raw, decodeErr := hex.DecodeString(strings.TrimPrefix(hexData, "0x"))
	if decodeErr != nil {
		return "", false
	}
	return t.lookupData(raw)
}
