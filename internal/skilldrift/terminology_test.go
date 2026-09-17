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
// The BAN IS ON THE PRODUCT NAME, not the string. `referrer-agent` and
// `referrer-signer` are the two MCP server names and appear on nearly every page —
// correctly, and the brand page says so explicitly. Only the capitalised forms and
// "referrer-agent protocol" name the product.
// Capitalised forms are matched EXACTLY. Lower-casing them first would make
// "Referrer-Agent" match the server name `referrer-agent`, which is on nearly every
// page and is correct — the first draft of this test did exactly that and reported
// the whole skill as broken.
var bannedExact = []string{
	"Referrer Agent",
	"Referrer-Agent",
}

// These name the product whatever their case, because no server is "the
// referrer-agent protocol".
var bannedAnyCase = []string{
	"referrer-agent protocol",
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
		t.Fatalf("the product is OpenSouk, and these name it something else:\n  %s\n\n"+
			"The server names `referrer-agent` and `referrer-signer` are fine and stay — "+
			"only the product name is banned (opensouk-docs src/pages/brand.mdx).",
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
