package skilldrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── the comparator, on synthetic input ────────────────────────────────────────

func TestCompare_CleanWhenTheyAgree(t *testing.T) {
	d := Compare(
		map[string]string{"query_registry": ServerAgent, "bind_escrow": ServerSigner},
		map[string]bool{"query_registry": true},
		map[string]bool{"bind_escrow": true},
	)
	if !d.Empty() {
		t.Errorf("expected no drift, got %+v", d)
	}
}

// The case this ticket exists for: a tool is registered and the skill never mentions it, so an
// agent hand-rolls what it could have called. bind_escrow was exactly this.
func TestCompare_FlagsUndocumentedTool(t *testing.T) {
	d := Compare(
		map[string]string{"query_registry": ServerAgent},
		map[string]bool{"query_registry": true},
		map[string]bool{"bind_escrow": true},
	)
	if len(d.Undocumented) != 1 || !strings.Contains(d.Undocumented[0], "bind_escrow") {
		t.Errorf("undocumented signer tool not reported: %+v", d)
	}
	if !strings.HasPrefix(d.Undocumented[0], ServerSigner+":") {
		t.Errorf("undocumented entry must name the server it is registered on: %q", d.Undocumented[0])
	}
}

// The opposite direction: the skill names a tool that no longer exists, so an agent following it
// calls into nothing.
func TestCompare_FlagsGhostTool(t *testing.T) {
	d := Compare(
		map[string]string{"sign_open_session_commitment": ServerSigner},
		map[string]bool{},
		map[string]bool{},
	)
	if len(d.Ghosts) != 1 || d.Ghosts[0] != "sign_open_session_commitment" {
		t.Errorf("ghost tool not reported: %+v", d)
	}
}

// Which server a tool lives on is part of the contract — calling the wrong one fails — so a tool
// documented under the wrong server is drift even though the name exists.
func TestCompare_FlagsWrongServer(t *testing.T) {
	d := Compare(
		map[string]string{"cast_review_votes": ServerSigner},
		map[string]bool{"cast_review_votes": true},
		map[string]bool{},
	)
	if len(d.WrongServer) != 1 {
		t.Fatalf("wrong-server attribution not reported: %+v", d)
	}
	if !strings.Contains(d.WrongServer[0], "cast_review_votes") ||
		!strings.Contains(d.WrongServer[0], ServerAgent) {
		t.Errorf("message must name the tool and where it really lives: %q", d.WrongServer[0])
	}
	// It is not also a ghost — the tool does exist.
	if len(d.Ghosts) != 0 {
		t.Errorf("a misattributed tool must not also be reported as a ghost: %+v", d)
	}
}

// ── the extractors ────────────────────────────────────────────────────────────

func TestRegistered_AnchorsOnAddToolNotCallTool(t *testing.T) {
	dir := t.TempDir()
	// A registration, and — the trap — an invocation of a tool registered on the OTHER server.
	// The signer calls the backend's cast_review_votes exactly like this for inline voting, and a
	// pattern matching any `Name:` beside a tool literal would credit the signer with registering it.
	src := `package x
func f() {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "bind_escrow",
		Description: "…",
	}, handleBindEscrow)
	session.CallTool(ctx, &sdkmcp.CallToolParams{Name: "cast_review_votes", Arguments: args})
}`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Registered(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got["bind_escrow"] {
		t.Error("did not find the registered tool")
	}
	if got["cast_review_votes"] {
		t.Error("counted a CallTool invocation as a registration")
	}
}

// The backend registers every tool through its own addTool wrapper (REF-441), which calls
// sdkmcp.AddTool once with a variable. Seeing only the SDK call found zero backend tools, and the
// check could not run at all from 2026-10-06 — long enough for an undocumented tool to ship.
func TestRegistered_SeesTheBackendAddToolWrapper(t *testing.T) {
	dir := t.TempDir()
	src := `package mcp
func addTool[In, Out any](srv *sdkmcp.Server, t *sdkmcp.Tool, h sdkmcp.ToolHandlerFor[In, Out]) {
	sdkmcp.AddTool(srv, t, func(ctx context.Context, req *sdkmcp.CallToolRequest, in In) (*sdkmcp.CallToolResult, Out, error) {
		return h(ctx, req, in)
	})
}
func (s *Server) register() {
	addTool(s.sdkServer, &sdkmcp.Tool{
		Name:        "get_products",
		Description: "…",
	}, s.handleGetProducts)
	s.addToolset(&sdkmcp.Tool{Name: "not_a_registration"})
}`
	if err := os.WriteFile(filepath.Join(dir, "tools.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Registered(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got["get_products"] {
		t.Error("did not find a tool registered through the addTool wrapper")
	}
	if got["not_a_registration"] {
		t.Error("counted a call to some other function as a registration")
	}
	if len(got) != 1 {
		t.Errorf("want exactly the one registered tool, got %v", got)
	}
}

// Tools constructed in tests are never served, so they must not count as registered — otherwise a
// fixture could satisfy the inventory and hide a tool nobody actually exposes.
func TestRegistered_IgnoresTestFiles(t *testing.T) {
	dir := t.TempDir()
	src := `package x
func f() { sdkmcp.AddTool(srv, &sdkmcp.Tool{Name: "only_in_tests"}, h) }`
	if err := os.WriteFile(filepath.Join(dir, "a_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Registered(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got["only_in_tests"] {
		t.Error("a tool registered only in a _test.go file was counted")
	}
}

func TestDocumented_AttributesRowsToTheHeadingAbove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tools.md")
	md := "# Inventory\n\n" +
		"## `referrer-agent` — protocol calls\n\n" +
		"| Tool | What it does |\n|---|---|\n| `query_registry` | search |\n" +
		"## `referrer-signer` — local key custody\n\n" +
		"| Tool | What it does |\n|---|---|\n| `bind_escrow` | bind |\n" +
		"Prose naming `pay_for_product` outside any table must not count as documented.\n"
	if err := os.WriteFile(path, []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Documented(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["query_registry"] != ServerAgent {
		t.Errorf("query_registry attributed to %q", got["query_registry"])
	}
	if got["bind_escrow"] != ServerSigner {
		t.Errorf("bind_escrow attributed to %q", got["bind_escrow"])
	}
	// Prose is deliberately not read: scanning it is what produced false positives on a parameter
	// name and on a sentence saying a tool had been removed.
	if _, ok := got["pay_for_product"]; ok {
		t.Error("a tool named in prose was counted as documented")
	}
}

func TestDocumented_FailsLoudlyIfTheFormatChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-tools.md")
	if err := os.WriteFile(path, []byte("# no server headings here\n| `x` | y |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Documented(path); err == nil {
		t.Error("an inventory with no server headings must error, not report zero tools")
	}
}
