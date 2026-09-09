package skilldrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The skill-drift workflow is duplicated in all three repositories rather than shared as a
// reusable workflow, because calling one across repos means trusting a mutable ref with secrets
// passed to it and branch protection is not available on this plan (REF-248).
//
// Duplication has exactly one cost — the copies drift — so this is the check that they do not. It
// compares everything from `permissions:` onward; the triggers above that line differ on purpose
// (backend watches dev, only agent-mcp carries the weekly canary).
func TestWorkflowCopiesAreIdentical(t *testing.T) {
	const marker = "permissions:"
	const rel = ".github/workflows/skill-drift.yml"

	repos := map[string]string{
		"agent-mcp": filepath.Join("..", ".."),
		"backend":   dirFromEnv(t, envBackend, filepath.Join("..", "..", "..", "backend")),
		"skills":    dirFromEnv(t, envSkills, filepath.Join("..", "..", "..", "skills")),
	}

	bodies := map[string]string{}
	for name, root := range repos {
		path := filepath.Join(root, rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			// A missing copy is drift of the worst kind: that repo silently stops checking, and a
			// check that never runs looks exactly like one that passes.
			t.Fatalf("%s has no %s (%v) — every repo that can cause drift must run the check", name, rel, err)
		}
		text := string(raw)
		i := strings.Index(text, marker)
		if i < 0 {
			t.Fatalf("%s/%s has no %q section — the shared body was restructured", name, rel, marker)
		}
		bodies[name] = text[i:]
	}

	ref := bodies["agent-mcp"]
	for name, body := range bodies {
		if body == ref {
			continue
		}
		t.Errorf("%s/%s has diverged from agent-mcp's copy below %q.\n"+
			"Copy agent-mcp's version verbatim from that line down; only the triggers above it may differ.\n"+
			"%s", name, rel, marker, firstDifference(ref, body))
	}
}

// firstDifference reports the first line that differs, so the failure says where rather than
// dumping two files at the reader.
func firstDifference(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "first difference at line " + itoa(i+1) + " of the shared body:\n  agent-mcp: " +
				wl + "\n  this repo: " + gl
		}
	}
	return "(no line difference found)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
