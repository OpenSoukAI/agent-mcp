package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// testVoteTransport, when non-nil, overrides URL dialing with an injected in-memory
// transport (tests only). Production leaves it nil and dials mcpURL.
var testVoteTransport sdkmcp.Transport

// voteRetryAttempts × voteRetryDelay must clear the indexer's worst-case latency:
// pollInterval (15s) + confirmationDepth (6 blocks) can require two ticks to clear
// safeHead, up to ~30s. 15×3s=45s leaves real margin over that (F-07).
const voteRetryAttempts = 15

// voteRetryDelay is a var (not const) so tests can shrink it; production is 3s.
var voteRetryDelay = 3 * time.Second

// castVotesViaBackend drives the backend's cast_review_votes two-step as an MCP client:
// step 1 (get commitment) → sign locally with the buyer key → step 2 (record), retrying
// step 2 while the escrow is not yet indexed. Returns the number of votes recorded.
func castVotesViaBackend(ctx context.Context, mcpURL string, agentID, escrowID int64, votes []voteArg, priv *ecdsa.PrivateKey) (int, error) {
	var transport sdkmcp.Transport = testVoteTransport
	if transport == nil {
		if mcpURL == "" {
			return 0, fmt.Errorf("REFERRER_AGENT_MCP_URL not set — required to submit inline votes")
		}
		transport = &sdkmcp.StreamableClientTransport{Endpoint: mcpURL}
	}

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "referrer-signer", Version: "1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return 0, fmt.Errorf("connect to referrer-agent MCP: %w", err)
	}
	defer session.Close()

	// ── step 1: obtain the commitment (votesHash/nonce/expiry/domain) ──
	step1Args := map[string]any{"agent_id": agentID, "escrow_id": escrowID, "votes": votes}
	var s1 struct {
		Commitment *voteCommitmentPayload `json:"commitment"`
		Nonce      string                 `json:"nonce"`
		Expiry     int64                  `json:"expiry"`
	}
	if err := callVoteTool(ctx, session, step1Args, &s1); err != nil {
		return 0, fmt.Errorf("cast_review_votes step 1: %w", err)
	}
	if s1.Commitment == nil {
		return 0, fmt.Errorf("cast_review_votes step 1 returned no commitment")
	}

	// ── sign locally with the buyer key ──
	digest, err := computeVoteDigest(*s1.Commitment)
	if err != nil {
		return 0, fmt.Errorf("compute vote digest: %w", err)
	}
	sig, err := crypto.Sign(digest, priv)
	if err != nil {
		return 0, fmt.Errorf("sign vote commitment: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1
	agentSig := "0x" + hex.EncodeToString(sig)

	// ── step 2: record, retrying past indexer lag ──
	step2Args := map[string]any{
		"agent_id": agentID, "escrow_id": escrowID, "votes": votes,
		"nonce": s1.Nonce, "expiry": s1.Expiry, "agent_sig": agentSig,
	}
	var lastErr error
	for attempt := 0; attempt < voteRetryAttempts; attempt++ {
		var s2 struct {
			Status        string `json:"status"`
			VotesRecorded int    `json:"votes_recorded"`
		}
		callErr := callVoteTool(ctx, session, step2Args, &s2)
		if callErr == nil {
			return s2.VotesRecorded, nil
		}
		lastErr = callErr
		if !strings.Contains(callErr.Error(), "not yet indexed") {
			return 0, callErr // a real validation error (bad review, all-self, …) — do not retry
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(voteRetryDelay):
		}
	}
	return 0, fmt.Errorf("votes not recorded after %d attempts: %w", voteRetryAttempts, lastErr)
}

// callVoteTool invokes cast_review_votes and decodes the structured result into out.
// A tool-level error (handler returned an error → IsError result) is surfaced as a Go error.
func callVoteTool(ctx context.Context, session *sdkmcp.ClientSession, args map[string]any, out any) error {
	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{Name: "cast_review_votes", Arguments: args})
	if err != nil {
		return err
	}
	if res.IsError {
		return fmt.Errorf("%s", toolErrorText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return fmt.Errorf("marshal tool result: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode tool result: %w", err)
	}
	return nil
}

// toolErrorText extracts the text of an IsError tool result.
func toolErrorText(res *sdkmcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			return tc.Text
		}
	}
	return "tool call failed"
}
