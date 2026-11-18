# mcp-guard

[![CI](https://github.com/aitools1/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aitools1/mcp-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A transparent MCP stdio proxy, sandbox, and secret filter** — wraps any MCP server (local or remote) to enforce security policies, redact secrets, measure tool token usage, and provide a live TUI dashboard.

## Why mcp-guard?

| Feature | Problem | Solution |
|---------|---------|----------|
| **Secret redaction** | LLMs leak API keys, tokens, JWTs in tool calls/responses | Automatic regex-based redaction in *both directions* (outgoing args + incoming responses) |
| **Sandbox isolation** | MCP servers run with full env access | Clears `env`, allows only `PATH`, `HOME` + explicit `allow_env`; restricts `cwd` |
| **Token economy** | Tool schemas consume LLM context tokens | Counts `tools/list` tokens, strips `disabled_tools` so LLM never sees them |
| **Live observability** | No visibility into MCP traffic | JSONL event log + `mcp-guard ui` (btop-style TUI): live traffic, latency, secrets, RAM/CPU |

## Quick Start

```bash
# 1. Install
cargo install --git https://github.com/aitools1/mcp-guard --locked

# 2. Scan existing MCP configs (OpenCode, Claude, Cursor) and create global config
mcp-guard import

# 3. Run a proxied server (plug into agent config instead of raw command)
mcp-guard run filesystem

# 4. Open the live dashboard
mcp-guard ui
```

## Architecture

```
┌─────────────┐     JSON-RPC 2.0      ┌──────────────────┐
│   Agent     │ ◄──────────────────►  │   mcp-guard      │
│ (OpenCode,  │   stdin / stdout      │  ┌────────────┐  │
│  Claude,    │                       │  │ Sandbox /  │  │
│  Cursor)    │                       │  │ Redaction  │  │
└─────────────┘                       │  └─────┬──────┘  │
                                      └──────┼──────────┘
        local stdio                        │
                              ┌────────────┴────────────┐
                              ▼                         ▼
                        ┌─────────┐               ┌─────────────┐
                        │  Child  │               │  Remote MCP │
                        │ Process │               │  (HTTP/SSE) │
                        └─────────┘               └─────────────┘
```

## Config (`~/.mcp-guard/mcp-guard.toml`)

```toml
# Local stdio server
[server.filesystem]
type = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
allowed_dir = "/home/user/projects"
allow_env = ["PATH", "HOME", "CUSTOM_VAR"]
disabled_tools = ["write_file"]

# Remote HTTP/SSE server
[server.github]
type = "remote"
url = "https://api.githubcopilot.com/mcp/"
disabled_tools = []

[server.github.headers]
Authorization = "Bearer {file:~/.config/mcp-guard/github-token.txt}"
```

### Key Fields

| Field | Stdio | Remote | Description |
|-------|-------|--------|-------------|
| `type` | `"stdio"` | `"remote"` | Transport mode |
| `command` | ✓ | | Binary to execute |
| `args` | ✓ | | Command arguments |
| `allowed_dir` | ✓ | | Working directory (sandbox) |
| `allow_env` | ✓ | | Env vars passed to child |
| `url` | | ✓ | Remote MCP endpoint |
| `headers` | | ✓ | Extra HTTP headers (supports `{file:...}` for token files) |
| `disabled_tools` | ✓ | ✓ | Tool names to hide/block |

## Commands

| Command | Description |
|---------|-------------|
| `mcp-guard import [--output PATH] [--dir DIR]` | Scan agent configs, write `mcp-guard.toml` |
| `mcp-guard run <server> [--config PATH]` | Start proxied server on stdio |
| `mcp-guard list [--config PATH]` | Show servers and policies |
| `mcp-guard ui [--config PATH]` | Open TUI dashboard |

### OpenCode Integration

After `mcp-guard import`, add to `~/.config/opencode/opencode.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-guard",
      "args": ["run", "filesystem"]
    }
  }
}
```

## TUI Dashboard (`mcp-guard ui`)

```
┌────────────────────────────────────────────────────────────────────┐
│ mcp-guard MCP proxy dashboard                         2 active │
│  SUMMARY   █ RUNNING  total RAM 45.2 MB  tool context ~1.2k tok  │
├────────────────────────┬──────────────────────────────────────────┤
│ SERVERS & TOOLS        │ LIVE TRAFFIC & SECURITY                  │
│ █ filesystem  RUNNING  │ [0012s] ✓ filesystem/read_file ok (8ms) │
│   echo                 │ [0008s] ⚠ github/leak SECRET REDACTED    │
│   leak                 │ [0003s] ⚠ filesystem/danger BLOCKED      │
│ █ github    RUNNING    │                                          │
│   [x] search           │                                          │
│   [ ] create_pr        │                                          │
├────────────────────────┴──────────────────────────────────────────┤
│ tab switch · j/k move · enter/space toggle tool · q quit          │
└────────────────────────────────────────────────────────────────────┘
```

### Keys

| Key | Action |
|-----|--------|
| `Tab` | Switch focus (Servers ↔ Log) |
| `j` / `k` / `↑` / `↓` | Navigate |
| `Enter` / `Space` | Expand server / Toggle tool enable |
| `q` / `Esc` | Quit |

## Event Log (`~/.mcp-guard/events.jsonl`)

```json
{"event":"server_started","ts_ms":1731900000000,"server":"github","proxy_pid":1234,"child_pid":5678}
{"event":"tools_listed","ts_ms":1731900001000,"server":"github","tools":5,"est_tokens":842,"names":["search","create_pr","get_file"]}
{"event":"tool_called","ts_ms":1731900002000,"server":"github","tool":"search","latency_ms":145,"status":"ok"}
{"event":"secret_redacted","ts_ms":1731900003000,"server":"github","secret_type":"GITHUB_PAT"}
```

## Redacted Secret Types

| Type | Pattern |
|------|---------|
| `OPENAI` | `sk-...` (20+ chars) |
| `ANTHROPIC` | `sk-ant-...` |
| `GITHUB_PAT` | `ghp_...` (36 chars) |
| `AWS_SECRET` | `aws_secret_access_key=...` |
| `JWT` | `eyJ...` |
| `BEARER` | `Bearer <token>` (20+ chars) |

Replaced inline with `[REDACTED:<TYPE>]`.

## Development

```bash
# Build
cargo build --workspace

# Test (unit + integration)
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Run TUI locally
cargo run --bin mcp-guard -- ui
```

## CI Pipeline (`.github/workflows/ci.yml`)

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --workspace
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo test --workspace
```

## License

MIT License — see [LICENSE](LICENSE).