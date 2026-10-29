package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestValidateVoteArgs(t *testing.T) {
	if err := validateVoteArgs(nil); err != nil {
		t.Errorf("nil votes must be valid (optional): %v", err)
	}
	if err := validateVoteArgs([]voteArg{}); err != nil {
		t.Errorf("empty votes must be valid (optional): %v", err)
	}
	if err := validateVoteArgs([]voteArg{{1, "a"}, {2, "b"}, {3, "c"}, {4, "d"}}); err == nil {
		t.Error("4 votes must be rejected (max 3)")
	}
	long := strings.Repeat("x", 281)
	if err := validateVoteArgs([]voteArg{{1, long}}); err == nil {
		t.Error("reasoning >280 chars must be rejected")
	}
	if err := validateVoteArgs([]voteArg{{1, ""}}); err == nil {
		t.Error("empty reasoning must be rejected")
	}
	if err := validateVoteArgs([]voteArg{{1, "solid latency benchmark"}}); err != nil {
		t.Errorf("valid single vote rejected: %v", err)
	}
}

// ── castVotesViaBackend: in-memory fake backend ────────────────────────────────

type fakeVoteStep struct {
	AgentID  int64     `json:"agent_id"`
	EscrowID int64     `json:"escrow_id"`
	Votes    []voteArg `json:"votes"`
	Nonce    string    `json:"nonce,omitempty"`
	Expiry   int64     `json:"expiry,omitempty"`
	AgentSig string    `json:"agent_sig,omitempty"`
}

type fakeVoteOut struct {
	Status        string                 `json:"status"`
	VotesRecorded int                    `json:"votes_recorded,omitempty"`
	Commitment    *voteCommitmentPayload `json:"commitment,omitempty"`
	Nonce         string                 `json:"nonce,omitempty"`
	Expiry        int64                  `json:"expiry,omitempty"`
}

// startFakeVoteBackend spins up an in-memory MCP server exposing cast_review_votes with the
// real two-step shape and injects its client transport via testVoteTransport. step 2 reports
// "not yet indexed" for the first notIndexedFirst calls, then succeeds. Signature is not
// verified here — this exercises client/retry orchestration, not EIP-712 (see
// TestComputeVoteDigestRoundTrip for that).
func startFakeVoteBackend(t *testing.T, notIndexedFirst int) {
	t.Helper()
	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "fake-opensouk-agent", Version: "0"}, nil)
	calls := 0
	sdkmcp.AddTool(srv, &sdkmcp.Tool{Name: "cast_review_votes"},
		func(_ context.Context, _ *sdkmcp.CallToolRequest, in fakeVoteStep) (*sdkmcp.CallToolResult, fakeVoteOut, error) {
			if in.AgentSig == "" { // step 1
				return nil, fakeVoteOut{
					Status: "awaiting_signature",
					Nonce:  "77777",
					Expiry: 9999999999,
					Commitment: &voteCommitmentPayload{
						Domain:  commitmentDomain{Name: "ReferrerVote", Version: "1", ChainID: 84532, VerifyingContract: "0x0000000000000000000000000000000000000001"},
						Message: voteCommitmentMessage{AgentID: fmt.Sprint(in.AgentID), EscrowID: fmt.Sprint(in.EscrowID), VotesHash: "0x" + strings.Repeat("11", 32), Nonce: "77777", Expiry: "9999999999"},
					},
				}, nil
			}
			// step 2
			calls++
			if calls <= notIndexedFirst {
				return nil, fakeVoteOut{}, fmt.Errorf("purchase for escrow %d not found (not yet indexed — retry shortly)", in.EscrowID)
			}
			return nil, fakeVoteOut{Status: "ok", VotesRecorded: len(in.Votes)}, nil
		})

	clientT, serverT := sdkmcp.NewInMemoryTransports()
	go func() { _ = srv.Run(context.Background(), serverT) }()
	testVoteTransport = clientT
	t.Cleanup(func() { testVoteTransport = nil })
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

func TestCastVotesViaBackend_HappyPath(t *testing.T) {
	startFakeVoteBackend(t, 0)
	n, err := castVotesViaBackend(context.Background(), "inmemory://test", 5, 55, []voteArg{{43, "influenced my choice"}}, newLocalSigner(testKey(t)))
	if err != nil {
		t.Fatalf("castVotesViaBackend: %v", err)
	}
	if n != 1 {
		t.Errorf("votes recorded: got %d want 1", n)
	}
}

func TestCastVotesViaBackend_RetriesPastIndexerLag(t *testing.T) {
	orig := voteRetryDelay
	voteRetryDelay = time.Millisecond
	t.Cleanup(func() { voteRetryDelay = orig })

	startFakeVoteBackend(t, 2) // first 2 step-2 calls report not-indexed
	n, err := castVotesViaBackend(context.Background(), "inmemory://test", 5, 55, []voteArg{{43, "influenced my choice"}}, newLocalSigner(testKey(t)))
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if n != 1 {
		t.Errorf("votes recorded: got %d want 1", n)
	}
}
