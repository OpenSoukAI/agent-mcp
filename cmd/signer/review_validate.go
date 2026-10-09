package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

// checkReviewContent asks the backend's dry-run (POST /v1/review/validate) whether it would
// accept content_json from this agent for this product, and refuses if not. The backend owns
// the schema (x402-review/1, picked by the product's category) and the offchain_proof binding,
// so neither is mirrored here. Fails closed: content the backend could not check is not hashed.
// reviewID is the on-chain id of a review being edited, nil for a new one: the backend then
// counts the review's own onchain_receipts as its own, not as reused (REF-425).
func checkReviewContent(ctx context.Context, agentID, merchantID *big.Int, productID [32]byte, content string, reviewID *big.Int) error {
	if !agentID.IsInt64() {
		return fmt.Errorf("agent_id %s is too large for the backend API (int64)", agentID)
	}
	mid, err := merchantIDForREST(merchantID)
	if err != nil {
		return err
	}
	base, err := apiBaseURL()
	if err != nil {
		return fmt.Errorf("cannot check content_json before signing, so nothing was sent: %w", err)
	}
	fields := map[string]any{
		"merchant_id":  mid,
		"agent_id":     agentID.Int64(),
		"product_id":   "0x" + hex.EncodeToString(productID[:]),
		"content_json": content,
	}
	if reviewID != nil {
		if !reviewID.IsInt64() {
			return fmt.Errorf("review_id %s is too large for the backend API (int64)", reviewID)
		}
		fields["review_id"] = reviewID.Int64()
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/review/validate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: restTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("could not check content_json against POST /v1/review/validate, so nothing was sent: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("could not read POST /v1/review/validate, so nothing was sent: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var be backendError
		_ = json.Unmarshal(raw, &be)
		return fmt.Errorf("could not check content_json against POST /v1/review/validate (status %d: %s), so nothing was sent",
			resp.StatusCode, be.Error)
	}
	var verdict struct {
		Valid *bool  `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &verdict); err != nil || verdict.Valid == nil {
		return fmt.Errorf("could not read POST /v1/review/validate, so nothing was sent")
	}
	if !*verdict.Valid {
		return fmt.Errorf("%s — the backend would refuse this review, so nothing was signed or sent. "+
			"Fix content_json against get_review_schema for the product's category", verdict.Error)
	}
	return nil
}
