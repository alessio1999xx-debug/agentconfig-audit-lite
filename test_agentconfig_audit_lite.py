"""Offline tests for agentconfig-audit-lite (temp-dir fixtures, no network).

Fake secrets are built at runtime so no real-looking token is stored in the repo.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import agentconfig_audit_lite as aca

GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
SK_KEY = "sk-" + "test0Key1" * 4


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = aca.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, rel, content):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
        return p

    def checks(self):
        _, findings, _ = aca.audit(self.d)
        return [f.check for f in findings], findings

    def test_inventory_lists_known_files(self):
        self.write("CLAUDE.md", "# rules\n")
        self.write("AGENTS.md", "# rules\n")
        self.write(".cursor/rules/style.mdc", "use tabs\n")
        self.write(".cursor/mcp.json", {"mcpServers": {}})
        self.write(".mcp.json", {"mcpServers": {}})
        self.write(".claude/settings.local.json", {})
        self.write("node_modules/pkg/CLAUDE.md", "ignored\n")
        self.write("README.md", "not an agent file\n")
        inv = dict(aca.discover(self.d))
        self.assertEqual(inv[".cursor/rules/style.mdc"], "rules")
        self.assertEqual(inv[".cursor/mcp.json"], "mcp")
        self.assertEqual(inv[".mcp.json"], "mcp")
        self.assertEqual(inv[".claude/settings.local.json"], "settings")
        self.assertEqual(inv["CLAUDE.md"], "rules")
        self.assertNotIn("README.md", inv)
        self.assertFalse(any(k.startswith("node_modules") for k in inv))

    def test_clean_project_exits_zero(self):
        self.write("AGENTS.md", "Run tests before committing.\n")
        self.write(".mcp.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "./docs"],
                                                        "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}})
        code, out, _ = run(self.d)
        self.assertEqual(code, 0, out)
        self.assertIn("OK: no findings", out)

    def test_plaintext_token_in_mcp_env_is_masked(self):
        self.write("claude_desktop_config.json", {"mcpServers": {"gh": {"command": "docker", "args": ["run", "ghcr.io/github/github-mcp-server"],
                                                                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH_TOKEN}}}})
        code, out, _ = run(self.d)
        self.assertEqual(code, 1)
        self.assertIn("plaintext-secret", out)
        self.assertIn("ghp_****", out)
        self.assertNotIn(GH_TOKEN, out)
        self.assertNotIn(GH_TOKEN[4:], out)

    def test_hardcoded_value_under_secret_key_name(self):
        self.write(".mcp.json", {"mcpServers": {"db": {"command": "uvx", "args": ["mcp-db==0.3.1"], "env": {"DB_PASSWORD": "hunter2hunter2!!"}}}})
        checks, _ = self.checks()
        self.assertEqual(checks, ["plaintext-secret"])

    def test_unpinned_npx_and_uvx(self):
        self.write(".cursor/mcp.json", {"mcpServers": {
            "a": {"command": "npx", "args": ["-y", "@scope/server"]},
            "b": {"command": "uvx", "args": ["mcp-server-fetch"]},
            "c": {"command": "npx", "args": ["-y", "pkg@latest"]},
            "d": {"command": "npx", "args": ["-y", "pkg@^1.2.0"]},
            "e": {"command": "npx -y other-server"},
            "ok1": {"command": "npx", "args": ["-y", "@scope/server@1.4.2"]},
            "ok2": {"command": "uvx", "args": ["--from", "mcp-git==0.6.2", "mcp-server-git"]},
            "ok3": {"command": "/usr/local/bin/uvx", "args": ["mcp-time@0.2.0"]},
        }})
        checks, findings = self.checks()
        self.assertEqual(checks.count("unpinned-server"), 5)
        names = " ".join(f.message for f in findings)
        for bad in ("'a'", "'b'", "'c'", "'d'", "'e'"):
            self.assertIn(bad, names)
        self.assertNotIn("'ok", names)

    def test_env_and_migrations_not_denied(self):
        self.write("CLAUDE.md", "Never edit migrations.\n")
        self.write(".env", "X=1\n")
        self.write("app/migrations/0001_init.py", "\n")
        self.write(".claude/settings.json", {"permissions": {"allow": ["Bash(npm test)"], "deny": []}})
        checks, _ = self.checks()
        self.assertIn("env-not-denied", checks)
        self.assertIn("migrations-not-denied", checks)

    def test_deny_rules_across_settings_files_pass(self):
        self.write(".env.local", "X=1\n")
        self.write("migrations/001.sql", "\n")
        self.write(".claude/settings.json", {"permissions": {"deny": ["Read(./.env*)", "Edit(./migrations/**)"]}})
        self.write(".claude/settings.local.json", {"permissions": {"deny": ["Write(./migrations/**)"]}})
        checks, _ = self.checks()
        self.assertEqual(checks, [])

    def test_pretooluse_hook_counts_as_protection(self):
        self.write(".env", "X=1\n")
        self.write(".claude/settings.json", {"hooks": {"PreToolUse": [{"matcher": "Read|Edit", "hooks": [{"type": "command", "command": "./guard.sh"}]}]}})
        checks, _ = self.checks()
        self.assertNotIn("env-not-denied", checks)

    def test_env_example_only_is_not_flagged(self):
        self.write(".env.example", "X=\n")
        self.write(".claude/settings.json", {"permissions": {}})
        self.assertEqual(self.checks()[0], [])

    def test_token_in_allow_rule(self):
        self.write(".claude/settings.local.json", {"permissions": {
            "allow": ["Bash(curl -H 'Authorization: Bearer %s' https://api.example.com)" % SK_KEY]}})
        code, out, _ = run(self.d)
        self.assertEqual(code, 1)
        self.assertIn("secret-in-allow-rule", out)
        self.assertNotIn(SK_KEY, out)

    def test_token_in_rule_file_reports_line(self):
        self.write("AGENTS.md", "# Setup\nuse key %s for the API\n" % SK_KEY)
        _, findings = self.checks()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "AGENTS.md:2")

    def test_invalid_json_is_note_not_crash(self):
        self.write(".vscode/mcp.json", "{ // comment\n }")
        code, out, _ = run(self.d)
        self.assertEqual(code, 0)
        self.assertIn("not valid JSON", out)

    def test_extra_file_and_usage_errors(self):
        outside = tempfile.mkdtemp()
        try:
            p = os.path.join(outside, "mcp.json")
            with open(p, "w") as fh:
                json.dump({"mcpServers": {"x": {"command": "npx", "args": ["srv"]}}}, fh)
            code, out, _ = run(self.d, "--file", p)
            self.assertEqual(code, 1)
            self.assertIn("unpinned-server", out)
        finally:
            shutil.rmtree(outside)
        self.assertEqual(run(os.path.join(self.d, "nope"))[0], 2)
        self.assertEqual(run(self.d, "--file", os.path.join(self.d, "nope.json"))[0], 2)

    def test_read_only(self):
        p = self.write(".mcp.json", {"mcpServers": {"x": {"command": "npx", "args": ["srv"], "env": {"API_KEY": SK_KEY}}}})
        before = {f: os.stat(os.path.join(r, f)).st_mtime_ns for r, _, fs in os.walk(self.d) for f in fs}
        run(self.d)
        after = {f: os.stat(os.path.join(r, f)).st_mtime_ns for r, _, fs in os.walk(self.d) for f in fs}
        self.assertEqual(before, after)
        with open(p) as fh:
            self.assertIn(SK_KEY, fh.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
