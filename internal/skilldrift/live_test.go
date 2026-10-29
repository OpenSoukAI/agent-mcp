package skilldrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sibling checkouts. REF-248 step 4 makes CI check these out and drop the env vars; until then the
// defaults are the local layout, where all three repos sit side by side.
const (
	envBackend = "SKILLDRIFT_BACKEND_DIR"
	envSkills  = "SKILLDRIFT_SKILLS_DIR"
)

func dirFromEnv(t *testing.T, env, fallback string) string {
	t.Helper()
	dir := os.Getenv(env)
	if dir == "" {
		dir = fallback
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		// Skipped, not failed: this repo can legitimately be checked out alone. The skip names the
		// override so a CI run that forgot to check out a sibling says so instead of going quiet.
		t.Skipf("%s not found at %q — set %s to the sibling checkout", filepath.Base(dir), dir, env)
	}
	return dir
}

// The check REF-248 asks for: what the two servers register versus what the skill documents.
//
// Deliberately compares declared sets. The inventory table is the skill's contract; the prose that
// teaches the flows is not machine-checked, because scanning it for tool-shaped words reported a
// parameter name and a "this tool no longer exists" sentence as missing tools. A noisy check gets
// disabled, and a disabled check is worse than none.
func TestSkillDocumentsEveryRegisteredTool(t *testing.T) {
	backend := dirFromEnv(t, envBackend, filepath.Join("..", "..", "..", "backend"))
	skills := dirFromEnv(t, envSkills, filepath.Join("..", "..", "..", "skills"))

	// Present but wrong is a failure, not a skip: if the paths resolve, the files must be there.
	agentDir := filepath.Join(backend, "internal", "mcp")
	agent, err := Registered(agentDir)
	if err != nil {
		t.Fatalf("reading opensouk-agent registrations: %v", err)
	}
	if len(agent) == 0 {
		t.Fatalf("no tools found in %s — the registration pattern or layout changed", agentDir)
	}

	signer, err := Registered(filepath.Join("..", "..", "cmd", "signer"))
	if err != nil {
		t.Fatalf("reading opensouk-signer registrations: %v", err)
	}
	if len(signer) == 0 {
		t.Fatal("no tools found in cmd/signer — the registration pattern changed")
	}

	inventory := filepath.Join(skills, "plugins", "opensoukai", "reference", "mcp-tools.md")
	documented, err := Documented(inventory)
	if err != nil {
		t.Fatalf("reading the skill inventory: %v", err)
	}

	d := Compare(documented, agent, signer)
	if d.Empty() {
		return
	}

	var b strings.Builder
	b.WriteString("the skill's tool inventory has drifted from what the servers register.\n")
	b.WriteString("Fix reference/mcp-tools.md in the skills repo (add a row when you add a tool).\n")
	if len(d.Undocumented) > 0 {
		b.WriteString("\nRegistered but NOT in the inventory — an agent cannot know these exist:\n")
		for _, s := range d.Undocumented {
			b.WriteString("  - " + s + "\n")
		}
	}
	if len(d.Ghosts) > 0 {
		b.WriteString("\nIn the inventory but registered NOWHERE — an agent calling these gets an error:\n")
		for _, s := range d.Ghosts {
			b.WriteString("  - " + s + "\n")
		}
	}
	if len(d.WrongServer) > 0 {
		b.WriteString("\nDocumented under the wrong MCP server — calling the wrong one fails:\n")
		for _, s := range d.WrongServer {
			b.WriteString("  - " + s + "\n")
		}
	}
	t.Error(b.String())
}
