#!/usr/bin/env python3
"""Report MCP-skill drift to Linear, idempotently (REF-248).

Reads the JSON that `cmd/skilldrift` prints and keeps exactly ONE open Linear issue in step with
it. Idempotency is the whole difficulty: three repositories trigger this check, so a naive
"create an issue when drift is found" buries the board within a day.

  drift, no open issue      -> create one
  drift, open issue exists  -> update its description to the current diff
  no drift, open issue      -> close it (the condition is machine-verifiable, and it reopens
                               itself the next time drift appears)
  no drift, no open issue   -> do nothing, say nothing

The issue is matched by exact title within the team, which needs no label to be created first.

Usage:
  report_skill_drift.py --diff diff.json [--source repo@sha] [--dry-run]

Environment:
  LINEAR_API_KEY   required unless --dry-run
  LINEAR_TEAM_ID   required unless --dry-run
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.linear.app/graphql"

# Matching is by exact title, so this string is load-bearing: changing it orphans the open issue
# and the next run opens a second one.
TITLE = "MCP skill inventory has drifted from the registered tools"

SECTIONS = [
    ("undocumented", "Registered but NOT in the inventory",
     "An agent cannot know these exist, so it will hand-roll what it could have called."),
    ("ghosts", "In the inventory but registered NOWHERE",
     "An agent following the skill calls these and gets an error."),
    ("wrong_server", "Documented under the wrong MCP server",
     "Calling the wrong server fails, so a correct name in the wrong table is still broken."),
]


def body(diff: dict, source: str | None) -> str:
    """Markdown description. Pure — this is what the tests cover."""
    lines = [
        "Raised automatically by the `skilldrift` check (REF-248). "
        "Fix `reference/mcp-tools.md` in the **skills** repo, then this issue closes itself on the "
        "next run.",
        "",
        f"- registered on `referrer-agent`: **{diff.get('registered_referrer_agent', '?')}**",
        f"- registered on `referrer-signer`: **{diff.get('registered_referrer_signer', '?')}**",
        f"- listed in the inventory: **{diff.get('documented', '?')}**",
    ]
    if source:
        lines.append(f"- triggered by: `{source}`")

    for key, heading, why in SECTIONS:
        items = diff.get(key) or []
        if not items:
            continue
        lines += ["", f"### {heading}", why, ""]
        lines += [f"- `{i}`" for i in items]

    lines += [
        "",
        "---",
        "The check compares declared sets — the inventory tables against the `sdkmcp.AddTool` "
        "registrations — and never scans prose. Prose scanning was tried first and reported a "
        "parameter name and a \"this tool was removed\" sentence as missing tools.",
    ]
    return "\n".join(lines)


def has_drift(diff: dict) -> bool:
    return any(diff.get(k) for k, _, _ in SECTIONS)


def graphql(query: str, variables: dict, key: str) -> dict:
    req = urllib.request.Request(
        API,
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Content-Type": "application/json", "Authorization": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"linear: HTTP {e.code}: {e.read()[:400].decode(errors='replace')}")
    if payload.get("errors"):
        raise SystemExit(f"linear: {json.dumps(payload['errors'])[:400]}")
    return payload["data"]


FIND = """
query($team: ID!, $title: String!) {
  issues(first: 1, filter: {
    team: { id: { eq: $team } }
    title: { eq: $title }
    state: { type: { nin: ["completed", "canceled"] } }
  }) { nodes { id identifier url } }
}"""

CREATE = """
mutation($team: String!, $title: String!, $description: String!) {
  issueCreate(input: { teamId: $team, title: $title, description: $description }) {
    success issue { identifier url }
  }
}"""

UPDATE = """
mutation($id: String!, $description: String!) {
  issueUpdate(id: $id, input: { description: $description }) { success issue { identifier url } }
}"""

# Closing needs a state of type "completed" on the team — ids are per-team, so resolve it.
DONE_STATE = """
query($team: ID!) {
  workflowStates(first: 1, filter: { team: { id: { eq: $team } }, type: { eq: "completed" } }) {
    nodes { id }
  }
}"""

CLOSE = """
mutation($id: String!, $state: String!) {
  issueUpdate(id: $id, input: { stateId: $state }) { success issue { identifier url } }
}"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", required=True, help="JSON from cmd/skilldrift")
    ap.add_argument("--source", default=None, help="what triggered the run, e.g. backend@abc123")
    ap.add_argument("--dry-run", action="store_true", help="print the action and body, call nothing")
    args = ap.parse_args()

    with open(args.diff) as f:
        diff = json.load(f)
    drift = has_drift(diff)

    if args.dry_run:
        print(f"action: {'create-or-update' if drift else 'close-if-open'}\n")
        print(body(diff, args.source) if drift else "(no drift — would close any open issue)")
        return 0

    key = os.environ.get("LINEAR_API_KEY")
    team = os.environ.get("LINEAR_TEAM_ID")
    if not key or not team:
        raise SystemExit("LINEAR_API_KEY and LINEAR_TEAM_ID are required")

    existing = graphql(FIND, {"team": team, "title": TITLE}, key)["issues"]["nodes"]

    if drift:
        desc = body(diff, args.source)
        if existing:
            got = graphql(UPDATE, {"id": existing[0]["id"], "description": desc}, key)["issueUpdate"]
            print(f"updated {got['issue']['identifier']} {got['issue']['url']}")
        else:
            got = graphql(CREATE, {"team": team, "title": TITLE, "description": desc}, key)["issueCreate"]
            print(f"created {got['issue']['identifier']} {got['issue']['url']}")
        return 0

    if not existing:
        print("in sync; no open drift issue")
        return 0

    states = graphql(DONE_STATE, {"team": team}, key)["workflowStates"]["nodes"]
    if not states:
        # Leave it open rather than guess a state: a stuck-open issue is recoverable, a wrongly
        # transitioned one is confusing.
        print(f"in sync, but {existing[0]['identifier']} has no completed state to move to")
        return 0
    got = graphql(CLOSE, {"id": existing[0]["id"], "state": states[0]["id"]}, key)["issueUpdate"]
    print(f"closed {got['issue']['identifier']} {got['issue']['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
