// Package skilldrift compares the MCP tools the two servers actually register against the tools
// the opensoukai skill documents (REF-248).
//
// The skill is what an agent reads before acting, so a tool missing from it makes the agent
// hand-roll something it could have called, and a tool named in it that no longer exists sends the
// agent down a dead end. Both have happened: the agent-less binding page told agents `bind` was
// "not an MCP tool" while `bind_escrow` was registered, and the "full tool reference" it pointed at
// was four signer tools out of date.
//
// The comparison is between DECLARED SETS — the inventory tables in reference/mcp-tools.md and the
// `sdkmcp.AddTool` registrations — never against prose. Scanning prose for tool-shaped words does
// not work: a first attempt flagged `submit_votes` (a parameter of pay_for_product) and
// `sign_open_session_commitment` (named in a sentence saying the tool no longer exists) as missing
// tools. A check that cries wolf gets switched off, so it reads only the table.
package skilldrift

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Server names, matching the two MCP server ids agents configure.
const (
	ServerAgent  = "referrer-agent"
	ServerSigner = "referrer-signer"
)

// registration matches `sdkmcp.AddTool(<srv>, &sdkmcp.Tool{Name: "x"`, and the same call through
// the backend's `addTool` wrapper (REF-441). Anchored on the call so a CallToolParams{Name: ...} is
// not mistaken for a registration — the signer calls the backend's cast_review_votes that way,
// which would otherwise look like the signer registering it.
var registration = regexp.MustCompile(`(?:\bsdkmcp\.AddTool|\baddTool)\([^,]+,\s*&sdkmcp\.Tool\{\s*Name:\s*"([a-z_]+)"`)

// inventoryRow matches a leading-cell tool name in a markdown table: `| `tool_name` | ... |`.
var inventoryRow = regexp.MustCompile("(?m)^\\|\\s*`([a-z_]+)`\\s*\\|")

// inventoryHeading matches the per-server section headings in the inventory.
var inventoryHeading = regexp.MustCompile("(?m)^## `([a-z-]+)`")

// Registered returns the tool names registered under dir, which should hold the Go sources that
// call sdkmcp.AddTool or the backend's addTool wrapper. Test files are skipped: they construct tools that are never served.
func Registered(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || len(name) > 8 && name[len(name)-8:] == "_test.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		for _, m := range registration.FindAllStringSubmatch(string(body), -1) {
			out[m[1]] = true
		}
	}
	return out, nil
}

// Documented returns the tools the inventory lists, keyed by tool name with the server whose
// section they appear under. Which server a tool lives on is part of the contract — calling the
// wrong one fails — so the section is captured, not just the name.
func Documented(inventoryPath string) (map[string]string, error) {
	body, err := os.ReadFile(inventoryPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", inventoryPath, err)
	}
	text := string(body)

	// Walk headings in order and attribute each table row to the heading above it.
	type section struct {
		server string
		start  int
	}
	var sections []section
	for _, m := range inventoryHeading.FindAllStringSubmatchIndex(text, -1) {
		sections = append(sections, section{server: text[m[2]:m[3]], start: m[0]})
	}
	if len(sections) == 0 {
		return nil, fmt.Errorf("%s has no `## `server`` headings — the inventory format changed", inventoryPath)
	}

	out := map[string]string{}
	for _, m := range inventoryRow.FindAllStringSubmatchIndex(text, -1) {
		server := ""
		for _, s := range sections {
			if s.start < m[0] {
				server = s.server
			}
		}
		if server == "" {
			continue // a table before the first server heading
		}
		out[text[m[2]:m[3]]] = server
	}
	return out, nil
}

// Diff reports what the inventory and the registrations disagree about.
type Diff struct {
	// Undocumented is registered but absent from the inventory: an agent cannot know it exists.
	Undocumented []string `json:"undocumented,omitempty"`
	// Ghosts are in the inventory but registered nowhere: an agent calling one gets an error.
	Ghosts []string `json:"ghosts,omitempty"`
	// WrongServer is documented under the wrong MCP server.
	WrongServer []string `json:"wrong_server,omitempty"`
}

func (d Diff) Empty() bool {
	return len(d.Undocumented) == 0 && len(d.Ghosts) == 0 && len(d.WrongServer) == 0
}

// Compare matches the inventory against the registrations of both servers.
func Compare(documented map[string]string, agent, signer map[string]bool) Diff {
	var d Diff
	serverOf := func(tool string) string {
		switch {
		case agent[tool]:
			return ServerAgent
		case signer[tool]:
			return ServerSigner
		}
		return ""
	}

	for tool := range agent {
		if _, ok := documented[tool]; !ok {
			d.Undocumented = append(d.Undocumented, ServerAgent+": "+tool)
		}
	}
	for tool := range signer {
		if _, ok := documented[tool]; !ok {
			d.Undocumented = append(d.Undocumented, ServerSigner+": "+tool)
		}
	}
	for tool, server := range documented {
		actual := serverOf(tool)
		switch {
		case actual == "":
			d.Ghosts = append(d.Ghosts, tool)
		case actual != server:
			d.WrongServer = append(d.WrongServer,
				fmt.Sprintf("%s: documented under %s, registered on %s", tool, server, actual))
		}
	}

	sort.Strings(d.Undocumented)
	sort.Strings(d.Ghosts)
	sort.Strings(d.WrongServer)
	return d
}
