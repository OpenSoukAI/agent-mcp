package main

import (
	"strings"
	"testing"
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
