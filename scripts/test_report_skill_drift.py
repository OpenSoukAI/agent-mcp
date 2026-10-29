#!/usr/bin/env python3
"""Tests for the pure parts of report_skill_drift (REF-248).

The GraphQL calls need a real key and are exercised only by a live run; everything that decides
WHAT to do is here, because that is where a mistake is silent — a wrong body is still a filed
issue, and a wrong has_drift() means either a missed regression or a daily false alarm.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import report_skill_drift as r  # noqa: E402

CLEAN = {"registered_opensouk_agent": 22, "registered_opensouk_signer": 13, "documented": 35}


class HasDrift(unittest.TestCase):
    def test_clean_is_not_drift(self):
        self.assertFalse(r.has_drift(CLEAN))

    def test_empty_lists_are_not_drift(self):
        # cmd/skilldrift omits empty fields, but a hand-made or older payload may send [].
        self.assertFalse(r.has_drift({**CLEAN, "undocumented": [], "ghosts": [], "wrong_server": []}))

    def test_each_category_counts(self):
        for key in ("undocumented", "ghosts", "wrong_server"):
            with self.subTest(key=key):
                self.assertTrue(r.has_drift({**CLEAN, key: ["x"]}))

    def test_unknown_key_is_not_drift(self):
        # A new field in the JSON must not be read as drift, or every run files an issue.
        self.assertFalse(r.has_drift({**CLEAN, "something_new": ["x"]}))


class Body(unittest.TestCase):
    def test_names_every_drifted_tool(self):
        b = r.body({**CLEAN, "undocumented": ["opensouk-signer: bind_escrow"],
                    "ghosts": ["sign_open_session_commitment"],
                    "wrong_server": ["cast_review_votes: documented under opensouk-signer, registered on opensouk-agent"]}, None)
        for needle in ("bind_escrow", "sign_open_session_commitment", "cast_review_votes"):
            self.assertIn(needle, b)

    def test_omits_sections_with_no_findings(self):
        b = r.body({**CLEAN, "undocumented": ["opensouk-agent: x"]}, None)
        self.assertIn("Registered but NOT in the inventory", b)
        self.assertNotIn("registered NOWHERE", b)
        self.assertNotIn("wrong MCP server", b)

    def test_says_where_to_fix_it(self):
        # The issue is read by someone who did not write the check.
        b = r.body({**CLEAN, "ghosts": ["x"]}, None)
        self.assertIn("mcp-tools.md", b)
        self.assertIn("skills", b)

    def test_includes_the_trigger_when_known(self):
        self.assertIn("backend@abc123", r.body({**CLEAN, "ghosts": ["x"]}, "backend@abc123"))
        self.assertNotIn("triggered by", r.body({**CLEAN, "ghosts": ["x"]}, None))

    def test_reports_the_counts(self):
        b = r.body({**CLEAN, "ghosts": ["x"]}, None)
        self.assertIn("22", b)
        self.assertIn("13", b)


class DryRun(unittest.TestCase):
    """--dry-run must never need a key, so it is safe to run in CI without secrets."""

    def run_dry(self, payload):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(payload, f)
            path = f.name
        out = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "report_skill_drift.py"),
             "--diff", path, "--dry-run"],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def test_drift_says_create_or_update(self):
        o = self.run_dry({**CLEAN, "ghosts": ["sign_open_session_commitment"]})
        self.assertIn("create-or-update", o)
        self.assertIn("sign_open_session_commitment", o)

    def test_clean_says_close(self):
        self.assertIn("close-if-open", self.run_dry(CLEAN))


if __name__ == "__main__":
    unittest.main(verbosity=2)
