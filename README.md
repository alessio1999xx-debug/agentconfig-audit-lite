# agentconfig-audit-lite: audit MCP config for secrets, unpinned servers and unsafe Claude Code settings

agentconfig-audit-lite helps with auditing MCP config for secrets and a quick check of the AI agent setup in one project: it lists the MCP server configs and agent rule files it finds, and flags plaintext tokens, `npx`/`uvx` MCP servers with no version pin, and Claude Code settings that don't keep the agent away from `.env` files and migrations. One file, Python 3.9+ standard library only, read-only, MIT.

- Nothing to `pip install`. No config, no state, no network calls.
- Secrets are shown as masked previews only (`ghp_****(40 chars)`), never in full.
- Flags: `--file`, `--version`.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/agentconfig-audit-lite/main/agentconfig_audit_lite.py
python3 agentconfig_audit_lite.py --help
```

## Scan a project's MCP config and CLAUDE.md / AGENTS.md rules

```bash
python3 agentconfig_audit_lite.py ~/code/my-app
# agentconfig-audit-lite 0.1.0: /home/me/code/my-app
#
# Found 3 agent config / rule file(s):
#   settings  .claude/settings.json
#   mcp       .mcp.json
#   rules     CLAUDE.md
#
# 3 finding(s):
#   FAIL  [unpinned-server] .mcp.json: server 'github' runs `npx @modelcontextprotocol/server-github` with no version pin (pin e.g. pkg@1.2.3 or pkg==1.2.3)
#   FAIL  [plaintext-secret] .mcp.json: server 'github' env GITHUB_PERSONAL_ACCESS_TOKEN = ghp_****(40 chars) (GitHub token)
#   FAIL  [migrations-not-denied] .claude/settings.json: project has a migrations dir but no Edit and Write deny rules for it and no PreToolUse hook

# also check a config that lives outside the project
python3 agentconfig_audit_lite.py . --file ~/.cursor/mcp.json --file ~/.claude/settings.json
```

## Which MCP configs and agent rule files it checks

Files (searched in the project dir, skipping `.git`, `node_modules`, virtualenvs and build dirs):

- MCP configs: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp.json`, `claude_desktop_config.json`, `mcp_config.json`
- Agent rule files: `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.cursor/rules/*`, `copilot-instructions.md`
- Claude Code settings: `.claude/settings.json`, `.claude/settings.local.json` (any `.claude/settings*.json`)

Checks:

| Check | What it flags |
| --- | --- |
| `plaintext-secret` | Known token formats (GitHub, OpenAI/Anthropic-style `sk-`, AWS, Slack, GitLab, Google, Stripe live, Bearer, private keys) in MCP `env`/`headers`/args and rule files, plus hardcoded values under names like `*_TOKEN` or `*_PASSWORD`. `${VAR}` references are fine. |
| `unpinned-server` | `npx`, `uvx` or `bunx` MCP servers with no exact version (`pkg`, `pkg@latest`, `pkg@^1.2`). `pkg@1.2.3` and `pkg==1.2.3` pass. |
| `env-not-denied` | The project has a `.env` file (not `.env.example`) and Claude Code settings have no `Read(...env...)` deny rule and no `PreToolUse` hook. |
| `migrations-not-denied` | The project has a `migrations` dir and settings don't deny both `Edit` and `Write` on it, and there's no `PreToolUse` hook. |
| `secret-in-allow-rule` | A token pasted into a `permissions.allow` rule in `.claude/settings*.json` (this happens when you approve a command that had a key in it). |

The two Claude Code settings checks only run when the project uses Claude Code (a `CLAUDE.md` or `.claude/settings*.json` exists). A `PreToolUse` hook is counted as protection, but the lite version doesn't check what the hook actually does. A rule in `CLAUDE.md` saying "don't touch .env" is not counted: it's an instruction, not a permission.

JSON with comments can't be parsed by the standard library; those files get a `NOTE` and a plain-text token scan only.

## Exit codes for CI or cron

| Exit code | Meaning |
| --- | --- |
| `0` | No findings |
| `1` | At least one finding |
| `2` | Bad arguments, project dir or `--file` not found |

## agentconfig-audit-lite vs AgentConfig Audit

agentconfig-audit-lite checks one project dir and prints a plain text list. That's it.

The full **[AgentConfig Audit](https://py-forge.com/products/agentconfig-audit-mcp-and-rules-scanner?utm_source=github&utm_medium=readme&utm_campaign=agentconfig-audit-lite)** helps with:

- finding the MCP configs installed on the machine (Claude Desktop, Cursor, VS Code, Windsurf, Codex, `~/.claude.json`) on macOS, Linux and Windows
- MCP servers given the whole filesystem (`/`, `~`, `/home`, `C:\`) and remote MCP endpoints with no auth header or plain `http://`
- hidden Unicode (zero-width and bidi override characters) and prompt-injection phrases in rule files
- JSON and SARIF 2.1.0 reports, written to a file if you want
- a suggested fix or command for each finding, severity levels and a `--strict` mode for HIGH/CRITICAL only

One-time payment, yours to keep. No subscription.

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=agentconfig-audit-lite).

## Tests

```bash
python3 test_agentconfig_audit_lite.py
```

The tests are offline and build their fixtures in temp dirs. Fake tokens are generated at runtime.

## License

MIT (this lite version). The full AgentConfig Audit is sold separately under its own license.
