package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── update_review_content_onchain ───────────────────────────────────────────────
//
// Sends ReviewRegistry.updateReviewContent, the on-chain half of editing a buyer review.
// The backend's update_review_content (referrer-agent) is the other half and REQUIRES this
// to have happened first: it refuses unless editedAt != 0, and it recomputes the content
// hash from the ON-CHAIN agentId/merchantId/productId, rejecting content whose hash does not
// match what this tool stored. That is why the hash here is computed from the ids read off
// the chain — never from caller-supplied ids. A hash over the wrong ids is accepted by the
// contract and then permanently un-syncable, with the 7-day window running down.

// editWindowSecs mirrors ReviewRegistry.EDIT_WINDOW (7 days). Used only to refuse a doomed
// call before spending gas; the chain remains authoritative.
const editWindowSecs int64 = 7 * 24 * 60 * 60

// proofTypeInSystemPurchase is IReviewRegistry.ProofType.InSystemPurchase — the only
// editable path (updateReviewContent reverts NotEditablePath for the other two).
const proofTypeInSystemPurchase uint8 = 2

type updateReviewOnchainInput struct {
	ReviewID    string `json:"review_id"`          // decimal; the ON-CHAIN review id
	ContentJSON string `json:"content_json"`       // the full replacement review content, same shape as at publish
	ChainID     string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env (default 84532)
}

type updateReviewOnchainOutput struct {
	TxHash      string `json:"tx_hash"`             // 0x-prefixed
	ReviewID    string `json:"review_id"`           // echoed
	ContentHash string `json:"content_hash"`        // 0x-prefixed; what the contract now stores
	AgentID     string `json:"agent_id"`            // the on-chain reviewer id whose key signed
	EditedAt    string `json:"edited_at,omitempty"` // unix seconds, from ReviewContentUpdated
	NextSteps   string `json:"next_steps"`
}

// updateReviewNextSteps is the required follow-up. The on-chain edit alone changes only the
// hash — the readable text, the alignment score, and the embedding all live in the backend
// and stay stale until the sync call lands.
const updateReviewNextSteps = "On-chain hash updated. Now call update_review_content " +
	"(referrer-agent) with the SAME review_id and the SAME content_json to sync the stored " +
	"text and re-run the alignment oracle — it verifies your content against this new " +
	"on-chain hash, so any difference is rejected."

// onChainReview is ReviewRegistry.Review as this tool needs it.
type onChainReview struct {
	AgentID     *big.Int
	MerchantID  *big.Int
	ProductID   [32]byte
	ContentHash [32]byte
	ProofType   uint8
	Timestamp   int64
	EditedAt    int64
}

// decodeGetReview decodes a getReview() return blob. Every field of the Review struct is a
// static type, so the tuple is returned inline as seven 32-byte slots in declaration order:
// agentId, merchantId, productId, contentHash, proofType, timestamp, editedAt.
func decodeGetReview(raw []byte) (onChainReview, error) {
	if len(raw) < 224 {
		return onChainReview{}, fmt.Errorf("getReview returned short data: %d bytes (want >= 224)", len(raw))
	}
	var r onChainReview
	r.AgentID = new(big.Int).SetBytes(raw[0:32])
	r.MerchantID = new(big.Int).SetBytes(raw[32:64])
	copy(r.ProductID[:], raw[64:96])
	copy(r.ContentHash[:], raw[96:128])
	r.ProofType = uint8(new(big.Int).SetBytes(raw[128:160]).Uint64())
	r.Timestamp = new(big.Int).SetBytes(raw[160:192]).Int64()
	r.EditedAt = new(big.Int).SetBytes(raw[192:224]).Int64()
	return r, nil
}

// editWindowState mirrors the contract's gate. The revert is
// `block.timestamp > timestamp + EDIT_WINDOW`, i.e. strict, so exactly at the boundary the
// window is still OPEN. Pure so it is testable without a chain.
func editWindowState(publishedAt, now int64) (closesAt int64, open bool) {
	closesAt = publishedAt + editWindowSecs
	return closesAt, now <= closesAt
}

func parseUpdateReviewInput(in updateReviewOnchainInput) (reviewID *big.Int, err error) {
	reviewID, ok := new(big.Int).SetString(strings.TrimSpace(in.ReviewID), 10)
	if !ok {
		return nil, fmt.Errorf("invalid review_id: %q (want a decimal string — the ON-CHAIN review id)", in.ReviewID)
	}
	if strings.TrimSpace(in.ContentJSON) == "" {
		return nil, fmt.Errorf("content_json is required (the full replacement review content)")
	}
	// The hash is over the raw string, so this does NOT reformat the content — it only
	// refuses input that cannot be valid review content, before a tx is paid for.
	if !json.Valid([]byte(in.ContentJSON)) {
		return nil, fmt.Errorf("content_json is not valid JSON")
	}
	return reviewID, nil
}

// updateReviewRevertTable maps the ReviewRegistry custom errors reachable from
// updateReviewContent to edit-specific advice. Note there is no EnforcedPause entry:
// unlike CommissionEscrow's write path, updateReviewContent carries no pause modifier.
var updateReviewRevertTable = newRevertTable(map[string]string{
	"ReviewNotFound(uint256)":              "no review exists on-chain for that review_id (is it the on-chain id, not the internal database id?)",
	"NotEditablePath(uint256)":             "only a buyer review published with an escrow proof (ProofType.InSystemPurchase) is editable — an admin-approved or oracle-attested review is not",
	"CallerNotAgentOwner(uint256,address)": "the signer key is neither the reviewer agent's owner nor its registered agent wallet — only those two may edit the review",
	"EditWindowClosed(uint256)":            "the 7-day on-chain edit window for this review has closed; the content is now immutable",
})

func handleUpdateReviewContentOnchain(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in updateReviewOnchainInput,
) (*sdkmcp.CallToolResult, updateReviewOnchainOutput, error) {
	reviewID, err := parseUpdateReviewInput(in)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, err
	}

	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	registryAddrHex := os.Getenv("REVIEW_REGISTRY_ADDRESS")
	if registryAddrHex == "" {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("REVIEW_REGISTRY_ADDRESS env var not set")
	}

	chainIDStr := in.ChainID
	if chainIDStr == "" {
		chainIDStr = os.Getenv("CHAIN_ID")
	}
	if chainIDStr == "" {
		chainIDStr = "84532" // Base Sepolia
	}
	chainIDInt, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("invalid chain id %q: %w", chainIDStr, err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	registryAddr := common.HexToAddress(registryAddrHex)

	// ── read the review: it supplies BOTH the hash preimage ids and the key to sign with ──
	callData, err := reviewRegistryABI.Pack("getReview", reviewID)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("pack getReview: %w", err)
	}
	raw, err := client.CallContract(ctx, ethereum.CallMsg{To: &registryAddr, Data: callData}, nil)
	if err != nil {
		if msg, ok := updateReviewRevertTable.lookupErr(err); ok {
			return nil, updateReviewOnchainOutput{}, fmt.Errorf("getReview(%s): %s", reviewID, msg)
		}
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("getReview(%s): %w (is review_id the ON-CHAIN id, and is BASE_RPC_URL on chain %d?)", reviewID, err, chainIDInt)
	}
	review, err := decodeGetReview(raw)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, err
	}
	if review.ProofType != proofTypeInSystemPurchase {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"review %s has proofType %d — only a buyer review published with an escrow proof (InSystemPurchase, %d) is editable",
			reviewID, review.ProofType, proofTypeInSystemPurchase)
	}
	closesAt, open := editWindowState(review.Timestamp, time.Now().Unix())
	if !open {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"the 7-day edit window for review %s closed at %s; its content is now immutable",
			reviewID, time.Unix(closesAt, 0).UTC().Format(time.RFC3339))
	}

	// The signing key is selected by the ON-CHAIN reviewer id, so a caller cannot CHOOSE to
	// sign with a different agent's key on purpose. It does not by itself stop a wrong-agent
	// edit: with AGENT_PRIVATE_KEY set, KeyFor's fallback returns that key for ANY agent id,
	// including one that is not review.AgentID. What actually blocks that case is the contract's
	// _isAgentCaller check plus the CallerNotAgentOwner entry in the revert map below — the
	// estimate fails, no gas is spent, and the caller gets a clear reason why.
	privKey, err := signerKeys.KeyFor(review.AgentID.String())
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("review %s belongs to agent %s: %w", reviewID, review.AgentID, err)
	}

	// Hash over the ON-CHAIN ids — the exact preimage the backend recomputes.
	newHash, err := computeContentHash(review.AgentID, review.MerchantID, review.ProductID, in.ContentJSON)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("compute content hash: %w", err)
	}
	if newHash == review.ContentHash {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"content_json hashes to the value already stored on-chain for review %s — nothing to update "+
				"(no transaction was sent). If you already ran this tool successfully for this edit, the "+
				"on-chain half is DONE — call update_review_content (referrer-agent) with this review_id "+
				"and the same content_json to finish syncing it", reviewID)
	}

	// ── send ───────────────────────────────────────────────────────────────────
	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("build transactor: %w", err)
	}
	contract := bind.NewBoundContract(registryAddr, reviewRegistryABI, client, client, client)

	tx, err := contract.Transact(auth, "updateReviewContent", reviewID, newHash)
	if err != nil {
		if msg, ok := updateReviewRevertTable.lookupErr(err); ok {
			return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent would revert: %s", msg)
		}
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent tx reverted: %s", tx.Hash().Hex())
	}

	out := updateReviewOnchainOutput{
		TxHash:      tx.Hash().Hex(),
		ReviewID:    reviewID.String(),
		ContentHash: "0x" + hex.EncodeToString(newHash[:]),
		AgentID:     review.AgentID.String(),
		NextSteps:   updateReviewNextSteps,
	}
	// ReviewContentUpdated(reviewId indexed, contentHash indexed, uint40 editedAt):
	// editedAt is the only non-indexed field, so it is the single word of Data.
	for _, lg := range receipt.Logs {
		if len(lg.Topics) >= 1 && lg.Topics[0] == reviewContentUpdatedTopic && len(lg.Data) >= 32 {
			out.EditedAt = new(big.Int).SetBytes(lg.Data[0:32]).String()
			break
		}
	}
	return nil, out, nil
}
