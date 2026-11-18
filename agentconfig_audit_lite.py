#!/usr/bin/env python3
"""agentconfig-audit-lite: audit MCP configs and AI agent rule files in one project.

Lists the MCP server configs and agent rule files in one project directory
(CLAUDE.md, AGENTS.md, .cursor/rules, .claude/settings*.json, .mcp.json,
.cursor/mcp.json, claude_desktop_config.json, ...) and flags:

  - plaintext tokens / API keys (masked in the report)
  - npx / uvx MCP servers launched without a version pin
  - Claude Code settings with no Read deny for .env files or no Edit/Write
    deny for migrations (and no PreToolUse hook)
  - tokens embedded in .claude/settings*.json permission allow rules

Read-only, plain text report, exit 1 when something is found. One file,
Python 3.9+ standard library only. MIT License.

Full version (machine-wide config discovery, JSON/SARIF reports, fix
commands, more checks): https://py-forge.com/products/agentconfig-audit-mcp-and-rules-scanner
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "0.1.0"

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
             "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".next"}

RULE_FILE_NAMES = {"claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
                   ".cursorrules", ".windsurfrules", "copilot-instructions.md"}
MCP_FILE_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json"}

# (regex, label). Group 1, when present, is the secret value itself.
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(sk-ant-[A-Za-z0-9_\-]{20,})", "Anthropic API key"),
    (r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})", "OpenAI-style API key"),
    (r"\b(ghp_[A-Za-z0-9]{36,})\b", "GitHub token"),
    (r"\b(gh[ousr]_[A-Za-z0-9]{36,})\b", "GitHub token"),
    (r"\b(github_pat_[A-Za-z0-9_]{40,})\b", "GitHub fine-grained token"),
    (r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", "GitLab token"),
    (r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b", "Slack token"),
    (r"\b(AKIA[0-9A-Z]{16})\b", "AWS access key ID"),
    (r"\b(AIza[0-9A-Za-z_\-]{35})\b", "Google API key"),
    (r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b", "Stripe live key"),
    (r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=]{20,})", "Bearer token"),
    (r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", "private key"),
]
SECRETISH_KEY = re.compile(r"(?i)(token|secret|passw(or)?d|api[_-]?key|access[_-]?key|private[_-]?key|auth)")
PLACEHOLDER = re.compile(r"(?i)^(\$\{?[A-Z0-9_:\-]+\}?|<[^>]*>|x+|\*+|your[_-].*|changeme|placeholder|example.*|\.\.\.)$")
RUNNERS = {"npx", "uvx", "bunx"}
RANGE_CHARS = set("^~><*x|")


def mask(value: str) -> str:
    """Masked preview: first 4 characters, then the length. Never the full value."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return value[:16] + "..."
    return "%s****(%d chars)" % (value[:4], len(value))


def find_secrets(text: str) -> List[Tuple[str, str]]:
    """Return (label, masked preview) for every known token pattern in text."""
    out: List[Tuple[str, str]] = []
    seen = set()
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            val = m.group(1)
            if PLACEHOLDER.match(val) or val in seen:
                continue
            if any(val in s or s in val for s in seen):
                continue
            seen.add(val)
            out.append((label, mask(val)))
    return out


class Finding:
    def __init__(self, path: str, check: str, message: str):
        self.path, self.check, self.message = path, check, message

    def __repr__(self) -> str:
        return "Finding(%r, %r, %r)" % (self.path, self.check, self.message)


# ---------------------------------------------------------------- discovery

def classify(rel: str) -> Optional[str]:
    """Return 'mcp', 'settings', 'rules' or None for a project-relative path."""
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1].lower()
    parent = parts[-2].lower() if len(parts) > 1 else ""
    if parent == ".claude" and re.match(r"^settings.*\.json$", name):
        return "settings"
    if name in MCP_FILE_NAMES:
        return "mcp"
    if name in RULE_FILE_NAMES:
        return "rules"
    if ".cursor" in [p.lower() for p in parts[:-1]] and "rules" in [p.lower() for p in parts[:-1]]:
        return "rules"
    if name.endswith(".mdc") and ".cursor" in [p.lower() for p in parts]:
        return "rules"
    return None


def discover(root: str) -> List[Tuple[str, str]]:
    """Walk one project dir; return sorted (relative path, kind)."""
    found: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fname), root)
            kind = classify(rel)
            if kind:
                found.append((rel, kind))
    return sorted(found)


# ---------------------------------------------------------------- checks

def _package_arg(cmd: str, args: List[str]) -> Optional[str]:
    """Return the package spec an npx/uvx/bunx call will run, or None."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--package", "-p", "--from", "--with") and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(("--package=", "--from=")):
            return a.split("=", 1)[1]
        if a.startswith("-"):
            i += 1
            continue
        return a
    return None


def is_pinned(spec: str) -> bool:
    if "==" in spec:
        return not any(c in spec.split("==", 1)[1] for c in "*")
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return False
    ver = body.split("@", 1)[1].strip()
    if not ver or ver.lower() in ("latest", "next", "canary", "beta"):
        return False
    if any(c in RANGE_CHARS for c in ver) or not ver[0].isdigit():
        return False
    return True


def check_mcp_servers(rel: str, data: Any) -> List[Finding]:
    out: List[Finding] = []
    if not isinstance(data, dict):
        return out
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = data.get("servers") if isinstance(data.get("servers"), dict) else {}
    # ~/.claude.json style: per-project mcpServers blocks
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                servers = dict(servers, **proj["mcpServers"])
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", "") or "")
        args = cfg.get("args") or []
        args = [str(a) for a in args] if isinstance(args, list) else []
        cmd_parts = cmd.split()
        if len(cmd_parts) > 1:  # "npx -y pkg" written as one string
            cmd, args = cmd_parts[0], cmd_parts[1:] + args
        runner = os.path.basename(cmd).lower()
        if runner.endswith(".cmd") or runner.endswith(".exe"):
            runner = runner[:-4]
        if runner in RUNNERS:
            spec = _package_arg(runner, args)
            if spec and not is_pinned(spec):
                out.append(Finding(rel, "unpinned-server",
                                   "server '%s' runs `%s %s` with no version pin (pin e.g. pkg@1.2.3 or pkg==1.2.3)"
                                   % (name, runner, spec)))
        for section in ("env", "headers"):
            block = cfg.get(section)
            if not isinstance(block, dict):
                continue
            for key, val in block.items():
                if not isinstance(val, str) or PLACEHOLDER.match(val.strip()) or "${" in val:
                    continue
                hits = find_secrets(val)
                if hits:
                    for label, prev in hits:
                        out.append(Finding(rel, "plaintext-secret",
                                           "server '%s' %s %s = %s (%s)" % (name, section, key, prev, label)))
                elif SECRETISH_KEY.search(key) and len(val) >= 12 and " " not in val:
                    out.append(Finding(rel, "plaintext-secret",
                                       "server '%s' %s %s = %s (hardcoded value)" % (name, section, key, mask(val))))
        for label, prev in find_secrets(" ".join(args + [str(cfg.get("url", ""))])):
            out.append(Finding(rel, "plaintext-secret", "server '%s' args/url contain %s %s" % (name, label, prev)))
    return out


def _rules(settings: List[Dict[str, Any]], key: str) -> List[str]:
    rules: List[str] = []
    for s in settings:
        perms = s.get("permissions") if isinstance(s, dict) else None
        if isinstance(perms, dict) and isinstance(perms.get(key), list):
            rules.extend(str(r) for r in perms[key])
    return rules


def _has_pretooluse(settings: List[Dict[str, Any]]) -> bool:
    for s in settings:
        hooks = s.get("hooks") if isinstance(s, dict) else None
        if isinstance(hooks, dict) and hooks.get("PreToolUse"):
            return True
    return False


def check_claude_settings(root: str, files: Dict[str, Any], has_env: bool, has_migrations: bool) -> List[Finding]:
    """files: rel path -> parsed JSON for .claude/settings*.json in the project root."""
    out: List[Finding] = []
    for rel, data in files.items():
        for rule in _rules([data], "allow"):
            for label, prev in find_secrets(rule):
                out.append(Finding(rel, "secret-in-allow-rule",
                                   "permissions.allow rule contains %s %s; rotate it and allow the command without the token"
                                   % (label, prev)))
    settings = list(files.values())
    where = ", ".join(sorted(files)) or ".claude/settings.json (missing)"
    hook = _has_pretooluse(settings)
    deny = _rules(settings, "deny")
    if has_env and not hook:
        if not any(re.match(r"^Read\(.*\.env", r) for r in deny):
            out.append(Finding(where, "env-not-denied",
                               "project has .env files but no Read deny rule such as \"Read(./.env*)\" and no PreToolUse hook"))
    if has_migrations and not hook:
        tools = {m.group(1) for r in deny for m in [re.match(r"^(Edit|Write|MultiEdit)\(.*migrations", r)] if m}
        if not ({"Edit", "Write"} <= tools):
            out.append(Finding(where, "migrations-not-denied",
                               "project has a migrations dir but no Edit and Write deny rules for it and no PreToolUse hook"))
    return out


def project_flags(root: str) -> Tuple[bool, bool]:
    has_env = has_mig = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(d.lower() == "migrations" for d in dirnames) or os.path.basename(dirpath).lower() == "migrations":
            has_mig = True
        if any(f == ".env" or f.startswith(".env.") for f in filenames
               if not f.endswith((".example", ".sample", ".template", ".dist"))):
            has_env = True
    return has_env, has_mig


def audit(root: str, extra_files: Iterable[str] = ()) -> Tuple[List[Tuple[str, str]], List[Finding], List[str]]:
    extra_files = list(extra_files)
    """Return (inventory, findings, notes). Read-only."""
    inventory = discover(root)
    for f in extra_files:
        name = os.path.basename(f)
        inventory.append((f, "settings" if name.startswith("settings") else
                          ("mcp" if name.endswith(".json") else "rules")))
    findings: List[Finding] = []
    notes: List[str] = []
    claude_settings: Dict[str, Any] = {}
    uses_claude = False
    for rel, kind in inventory:
        path = rel if os.path.isabs(rel) or rel in extra_files else os.path.join(root, rel)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            notes.append("%s: could not read (%s)" % (rel, exc.strerror or exc))
            continue
        if os.path.basename(rel).lower().startswith("claude") or kind == "settings":
            uses_claude = True
        if kind in ("mcp", "settings"):
            try:
                data = json.loads(text)
            except ValueError:
                notes.append("%s: not valid JSON, skipped structured checks" % rel)
                data = None
                for label, prev in find_secrets(text):
                    findings.append(Finding(rel, "plaintext-secret", "%s %s" % (label, prev)))
            if data is not None:
                findings.extend(check_mcp_servers(rel, data))
                if kind == "settings":
                    if os.path.dirname(rel).replace("\\", "/") == ".claude":
                        claude_settings[rel] = data
                    else:
                        for r in _rules([data], "allow"):
                            for label, prev in find_secrets(r):
                                findings.append(Finding(rel, "secret-in-allow-rule",
                                                        "permissions.allow rule contains %s %s" % (label, prev)))
        else:
            for n, line in enumerate(text.splitlines(), 1):
                for label, prev in find_secrets(line):
                    findings.append(Finding("%s:%d" % (rel, n), "plaintext-secret", "%s %s" % (label, prev)))
    if uses_claude or claude_settings:
        has_env, has_mig = project_flags(root)
        findings.extend(check_claude_settings(root, claude_settings, has_env, has_mig))
    return inventory, findings, notes


def render(root: str, inventory, findings, notes) -> str:
    lines = ["agentconfig-audit-lite %s: %s" % (__version__, os.path.abspath(root)), ""]
    lines.append("Found %d agent config / rule file(s):" % len(inventory))
    for rel, kind in inventory:
        lines.append("  %-9s %s" % (kind, rel))
    if not inventory:
        lines.append("  (none)")
    lines.append("")
    for n in notes:
        lines.append("NOTE  " + n)
    if findings:
        lines.append("%d finding(s):" % len(findings))
        for f in findings:
            lines.append("  FAIL  [%s] %s: %s" % (f.check, f.path, f.message))
    else:
        lines.append("OK: no findings")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentconfig-audit-lite",
        description="Read-only audit of MCP configs and AI agent rule files in one project dir. "
                    "Exit 0 = clean, 1 = findings, 2 = usage error.")
    ap.add_argument("project", nargs="?", default=".", help="project directory to scan (default: .)")
    ap.add_argument("--file", action="append", default=[], metavar="PATH",
                    help="also check this config file, e.g. ~/.cursor/mcp.json (repeatable)")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args(argv)
    if not os.path.isdir(args.project):
        print("error: not a directory: %s" % args.project, file=sys.stderr)
        return 2
    extra = [os.path.expanduser(f) for f in args.file]
    for f in extra:
        if not os.path.isfile(f):
            print("error: file not found: %s" % f, file=sys.stderr)
            return 2
    inventory, findings, notes = audit(args.project, extra)
    print(render(args.project, inventory, findings, notes))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
