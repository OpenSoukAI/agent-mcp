package main

import (
	"context"
	"errors"
	"math"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// stubHeaderReader is a headerReader that returns a fixed header or error.
type stubHeaderReader struct {
	header *types.Header
	err    error
	calls  int
	gotNum *big.Int
	numSet bool
}

func (s *stubHeaderReader) HeaderByNumber(_ context.Context, number *big.Int) (*types.Header, error) {
	s.calls++
	s.gotNum, s.numSet = number, true
	return s.header, s.err
}

func TestChainNow_ReturnsLatestBlockTimestamp(t *testing.T) {
	s := &stubHeaderReader{header: &types.Header{Time: 1_770_000_000}}

	got, err := chainNow(context.Background(), s)
	if err != nil {
		t.Fatalf("chainNow: %v", err)
	}
	if got != 1_770_000_000 {
		t.Fatalf("chainNow = %d, want 1770000000", got)
	}
	// nil block number is what asks for the LATEST block; any other value would read a
	// historical block and silently judge every window against a stale clock.
	if !s.numSet || s.gotNum != nil {
		t.Fatalf("HeaderByNumber called with %v, want nil (latest)", s.gotNum)
	}
}

func TestChainNow_PropagatesRPCError(t *testing.T) {
	wantErr := errors.New("connection refused")
	s := &stubHeaderReader{err: wantErr}

	_, err := chainNow(context.Background(), s)
	if err == nil {
		t.Fatal("chainNow returned no error for a failing RPC")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error does not wrap the RPC error: %v", err)
	}
	if !strings.Contains(err.Error(), "latest block timestamp") {
		t.Fatalf("error lacks context about what failed: %v", err)
	}
}

// A nil header with a nil error is what an RPC returns for an unknown block. Without the
// explicit check this would panic on h.Time and kill the tool with a stack trace instead
// of a message.
func TestChainNow_RejectsNilHeader(t *testing.T) {
	s := &stubHeaderReader{}

	if _, err := chainNow(context.Background(), s); err == nil {
		t.Fatal("chainNow accepted a nil header")
	}
}

// Header.Time is a uint64 and every gate consuming it compares as int64. An out-of-range
// value must be refused rather than wrapped to a negative timestamp, which would make
// every window look long closed (or long open).
func TestChainNow_RejectsInt64Overflow(t *testing.T) {
	s := &stubHeaderReader{header: &types.Header{Time: math.MaxUint64}}

	if _, err := chainNow(context.Background(), s); err == nil {
		t.Fatal("chainNow accepted a timestamp that does not fit in int64")
	}
}

// TestWindowGatesAreFedTheChainClock is a source-level guard, and deliberately so.
//
// Both window gates are pure functions over an injected `now`, and both are already tested
// at their boundaries — so the only defect left in this area is passing the WRONG clock into
// them. That is a single token on a single line, it type-checks either way, and every
// behavioural test in this package still passes with `time.Now()` restored, because none of
// them can reach the handler's preflight without a chain. Nothing but the source itself
// distinguishes the two, so the source is what this asserts.
//
// Reintroducing the defect (swapping either `now` back to `time.Now().Unix()`) fails this test.
func TestWindowGatesAreFedTheChainClock(t *testing.T) {
	// Matches a call to either gate and captures its argument list.
	gateCall := regexp.MustCompile(`(?:fallbackEligibility|editWindowState)\(([^)]*)\)`)

	for _, file := range []string{"settle_fallback.go", "update_review.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		matches := gateCall.FindAllStringSubmatch(string(src), -1)
		if len(matches) == 0 {
			t.Fatalf("%s: found no call to a window gate — has it been renamed? "+
				"This guard is now blind and must be updated with it.", file)
		}
		for _, m := range matches {
			args := m[1]
			if strings.Contains(args, "time.Now") {
				t.Errorf("%s: window gate is fed the wall clock: %s. "+
					"The contracts compare block.timestamp, so this must be chainNow(ctx, client) — "+
					"a wall-clock comparison is only correct while the chain's clock agrees with this "+
					"machine's, which is not true on any test chain whose time has been moved (REF-263).",
					file, m[0])
			}
		}
	}
}
