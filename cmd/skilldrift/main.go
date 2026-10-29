// Command skilldrift compares the MCP tools the two servers register against the tools the
// opensoukai skill documents, and prints the difference as JSON (REF-248).
//
// Exit codes are the point of this binary existing alongside the package's Go test: CI has to tell
// "the skill has drifted" (an expected finding — report it and move on) from "the check could not
// run" (a broken check, which must be loud). A test exits 1 for both.
//
//	0  in sync
//	2  drift found — JSON on stdout
//	1  could not run: a source directory or the inventory is missing or unreadable
//
// A missing directory is exit 1, not a silent success: a check that cannot run must never look
// like a check that passed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/OpenSoukAI/agent-mcp/internal/skilldrift"
)

const (
	exitDrift  = 2
	exitBroken = 1
)

func main() {
	backend := flag.String("backend", "", "path to a backend checkout (required)")
	skills := flag.String("skills", "", "path to a skills checkout (required)")
	signer := flag.String("signer", ".", "path to this agent-mcp checkout")
	flag.Parse()

	if *backend == "" || *skills == "" {
		fail("both -backend and -skills are required")
	}

	agentDir := filepath.Join(*backend, "internal", "mcp")
	agent, err := skilldrift.Registered(agentDir)
	if err != nil {
		fail("reading opensouk-agent registrations: %v", err)
	}
	if len(agent) == 0 {
		// Notably reachable: backend's default branch is main, where internal/ does not exist —
		// its code lives on dev. Checking out the wrong ref lands here rather than reporting
		// every tool as undocumented.
		fail("no tools found in %s — wrong ref checked out, or the registration pattern changed", agentDir)
	}

	signerDir := filepath.Join(*signer, "cmd", "signer")
	signerTools, err := skilldrift.Registered(signerDir)
	if err != nil {
		fail("reading opensouk-signer registrations: %v", err)
	}
	if len(signerTools) == 0 {
		fail("no tools found in %s — wrong ref checked out, or the registration pattern changed", signerDir)
	}

	inventory := filepath.Join(*skills, "plugins", "opensoukai", "reference", "mcp-tools.md")
	documented, err := skilldrift.Documented(inventory)
	if err != nil {
		fail("reading the skill inventory: %v", err)
	}

	d := skilldrift.Compare(documented, agent, signerTools)
	out, err := json.MarshalIndent(struct {
		skilldrift.Diff
		RegisteredAgent  int `json:"registered_opensouk_agent"`
		RegisteredSigner int `json:"registered_opensouk_signer"`
		Documented       int `json:"documented"`
	}{d, len(agent), len(signerTools), len(documented)}, "", "  ")
	if err != nil {
		fail("marshal diff: %v", err)
	}
	fmt.Println(string(out))

	if !d.Empty() {
		os.Exit(exitDrift)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "skilldrift: "+format+"\n", args...)
	os.Exit(exitBroken)
}
