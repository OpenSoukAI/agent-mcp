package skilldrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const workflowRel = ".github/workflows/skill-drift.yml"

// The skill-drift workflow is duplicated rather than shared as a reusable workflow, because
// calling one across repos means trusting a mutable ref with secrets passed to it and branch
// protection is not available on this plan (REF-248).
//
// Duplication has exactly one cost — the copies drift — so this is the check that they do not. It
// compares everything from `permissions:` onward; the triggers above that line differ on purpose
// (backend watches dev, only agent-mcp carries the daily canary).
func TestWorkflowCopiesAreIdentical(t *testing.T) {
	const marker = "permissions:"
	const rel = workflowRel

	// skills is absent on purpose — see TestSkillsRepoHasNoWorkflow.
	repos := map[string]string{
		"agent-mcp": filepath.Join("..", ".."),
		"backend":   dirFromEnv(t, envBackend, filepath.Join("..", "..", "..", "backend")),
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

// The skills repo must NOT carry this workflow, and that is a security constraint rather than an
// omission (REF-248).
//
// skills is public. The job needs a token that reads backend and agent-mcp, which stay private, so
// a copy in a public repo turns that repo into a lever for reading private source — and secrets
// reach a workflow there the moment anyone adds a fork-triggerable event (`pull_request_target`,
// `workflow_run`, `issue_comment`) or a third-party action, none of which is unlikely over time.
//
// Adding the check back would look like an improvement to whoever does it — "why isn't the repo
// that owns the inventory checking it?" — so the reason is asserted here rather than left in a
// comment nobody reads. The cost of not running it there is latency, not coverage: drift
// originating in skills is caught by the next backend or agent-mcp merge, or by the daily canary.
func TestSkillsRepoHasNoWorkflow(t *testing.T) {
	skills := dirFromEnv(t, envSkills, filepath.Join("..", "..", "..", "skills"))
	path := filepath.Join(skills, workflowRel)

	if _, err := os.Stat(path); err == nil {
		t.Errorf("%s exists.\n"+
			"skills is a PUBLIC repo and this job needs a token that reads the private backend and\n"+
			"agent-mcp repos — putting it there makes a public repo a lever for reading private code.\n"+
			"Run the check from backend or agent-mcp instead; skills-originated drift is caught by\n"+
			"their merges or the daily canary.", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("could not determine whether %s exists: %v", path, err)
	}
}
