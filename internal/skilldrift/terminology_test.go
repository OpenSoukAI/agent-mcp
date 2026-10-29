package skilldrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The docs site bans "Referrer Agent" as a product name and enforces it in its own
// suite (opensouk-docs test/hygiene.test.ts, "terminology"). That check covers the
// docs site alone, and the skill is the surface where drift costs most: an agent
// reads it and acts without a human seeing the text. So the same ban runs here.
//
// The MCP servers were `referrer-agent` / `referrer-signer` until they became
// `opensouk-agent` / `opensouk-signer`, so the old server names are banned too: a
// skill page still naming them tells an agent to call a server that no longer exists.
var bannedExact = []string{
	"Referrer Agent",
}

var bannedAnyCase = []string{
	"referrer-agent",
	"referrer-signer",
	"referrer agent protocol",
}

func TestSkillNamesTheProductOpenSouk(t *testing.T) {
	skills := dirFromEnv(t, envSkills, filepath.Join("..", "..", "..", "skills"))
	root := filepath.Join(skills, "plugins", "opensoukai")

	// Present but empty is a failure, not a pass. A reader that silently finds nothing
	// is how this suite has reported false greens before.
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Fatalf("no .md files under %s — the skill moved, or the path is wrong", root)
	}

	var offenders []string
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		rel, _ := filepath.Rel(skills, path)
		for i, line := range strings.Split(string(b), "\n") {
			if namesTheProductWrong(line) {
				offenders = append(offenders, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("the product is OpenSouk, and these name it (or its MCP servers) something else:\n  %s\n\n"+
			"The MCP servers are `opensouk-agent` and `opensouk-signer`.",
			strings.Join(offenders, "\n  "))
	}
}

func namesTheProductWrong(line string) bool {
	for _, banned := range bannedExact {
		if strings.Contains(line, banned) {
			return true
		}
	}
	lower := strings.ToLower(line)
	for _, banned := range bannedAnyCase {
		if strings.Contains(lower, banned) {
			return true
		}
	}
	return false
}
