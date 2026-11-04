# scguard-mcp

A **read-only MCP server for software supply-chain security triage**. It connects an AI
assistant (Claude Desktop, VS Code, any MCP client) to GitHub code scanning and Dependabot
alerts, enriches them with **OSV**, **FIRST EPSS** and **CISA KEV**, and returns a
prioritised, explainable P1–P4 list. It's built with guardrails for least privilege,
allowlists, input validation, secret handling, rate limiting and audit logging.

Project 2 of the series. Project 1 (`supply-chain-lab`) produces the alerts; this server
triages them.

| EPAM requirement | Where |
|---|---|
| Develop MCP servers/tools to automate security checks, enrichment, triage, reporting across repos | 3 tools: `list_security_alerts`, `enrich_vulnerability`, `triage_repository` |
| Guardrails for MCP flows: least privilege, allowlists, input validation, secure secrets handling, audit logs, monitoring | See [Guardrails](#guardrails), each one covered by a test |
| Dependency risk management, GHAS integration | Reads Dependabot + code scanning (CodeQL, Grype, Scorecard SARIF) via the GitHub REST API |
| LLMs in security automation | The model calls the tools; results are structured (JSON schema) and the free text in them is sanitised |

## Tools

| Tool | Input | Output |
|---|---|---|
| `list_security_alerts` | `repo`, `source` (all / code_scanning / dependabot), `severity`, `tool_name` | Normalised open alerts with extracted CVE/GHSA ids and fixed version |
| `enrich_vulnerability` | `vuln_id` (CVE / GHSA / PYSEC) | OSV summary, aliases, CVSS, fixed versions; EPSS score and percentile; KEV status, due date, ransomware flag |
| `triage_repository` | `repo`, `max_items` | Alerts + enrichment → P1–P4 with a reason per item, counts, and a markdown table |

**Priority policy** (deterministic and explainable, see `triage.py`):

| Priority | Rule |
|---|---|
| P1 | CVE is in CISA KEV (known exploited in the wild) |
| P2 | EPSS ≥ 0.10, or severity critical |
| P3 | severity high |
| P4 | everything else |

The 0.10 EPSS threshold is **a policy choice I made**, not an industry standard. It's a
setting (`epss_priority_threshold`). GHSA-only findings (e.g. Grype SARIF rule ids like
`GHSA-wf93-45jw-7689-pip`) are resolved to CVEs through OSV aliases before scoring.

## Guardrails

The MCP spec says servers **MUST** validate tool inputs, implement access controls, rate-limit
tool invocations and sanitise tool outputs ([spec, Tools › Security considerations][spec-tools]).

| Control | Implementation | Test |
|---|---|---|
| **Access control: repo allowlist** | `SCGUARD_ALLOWED_REPOS`; empty means the server **refuses to start** (fail-closed). Same error whether or not the repo exists | `test_repo_not_in_allowlist_is_denied_without_network` |
| **Input validation** | Strict regexes for `owner/repo` and CVE/GHSA/PYSEC ids; enums and length/pattern limits in the JSON schema the client sees. Rejected before any network call | `test_malformed_repo_rejected`, `test_malformed_vuln_id_rejected`, `test_schema_rejects_bad_enum_and_tool_name` |
| **Read-only by construction** | HTTP layer only exposes GET; tools annotated `read_only_hint=True`, `destructive_hint=False` | `test_tools_are_listed_and_read_only` |
| **Least-privilege token** | Fine-grained PAT, read-only *Code scanning alerts* + *Dependabot alerts*, selected repos only | — (configuration, see Setup) |
| **Secret handling** | Token only from env; sent **only** to `api.github.com`; redacted (`ghp_…`, `github_pat_…` and the literal value) from audit logs | `test_token_never_sent_to_third_parties`, `test_audit_log_records_calls_and_never_the_token` |
| **Egress allowlist** | Only `api.github.com`, `api.osv.dev`, `api.first.org`, `www.cisa.gov`, `raw.githubusercontent.com`; HTTPS only; redirects not followed; size and time caps | `test_egress_allowlist_blocks_other_hosts` |
| **Output sanitisation (prompt-injection defence)** | Free text from repos/advisories has control and bidi characters stripped, is length-capped and returned as data fields; server instructions tell the model it's data, not instructions | `test_untrusted_text_is_sanitised` |
| **Rate limiting** | 30 calls / 60 s sliding window (configurable) | `test_rate_limit` |
| **Audit log** | JSONL per call: timestamp, tool, args, outcome (`ok` / `denied` / `error`), duration, result count. Written to a file, never stdout (stdout carries the JSON-RPC stream for stdio servers) | `test_audit_log_records_calls_and_never_the_token` |
| **Graceful degradation** | GitHub 403/404 (feature off, no analysis) becomes a `notes` entry, not a crash | `test_feature_disabled_is_a_note_not_a_crash` |

**Known limitation:** arguments rejected by the JSON-schema validation (e.g. `severity: "urgent"`)
are refused by the SDK before the tool body runs. They're logged by the SDK on stderr, but not
in the JSONL audit file.

Also note what the spec puts on the **client** side: human-in-the-loop confirmation, showing
tool inputs before calls, and treating tool annotations as untrusted unless they come from a
trusted server ([spec][spec-tools]). A server can't enforce those. This is why it's read-only.

## Setup

### 1. Token (least privilege)

GitHub › Settings › Developer settings › **Fine-grained personal access tokens** › Generate:
- Repository access: **Only select repositories** → your `supply-chain-lab`
- Repository permissions: **Code scanning alerts: Read-only**, **Dependabot alerts: Read-only**
  (Metadata: Read-only is added automatically)
- Expiration: 30 days

These are the permissions the REST docs list for the two endpoints
([code scanning][gh-cs], [Dependabot][gh-dep]).

### 2. Install and test

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1       # if blocked: Set-ExecutionPolicy -Scope Process RemoteSigned
pip install -e ".[dev]"
pytest -q                           # 28 tests, no network needed
```

**Linux / macOS (bash):**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

### 3. Live smoke test against your repo (real APIs, over stdio)

**Windows (PowerShell):** the token is read without echoing it, so it never appears in your
terminal history or in output you might share.
```powershell
$env:GITHUB_TOKEN = Read-Host -MaskInput "GitHub token"
$env:SCGUARD_ALLOWED_REPOS = "<you>/<repo>"        # owner/repo, NOT a URL
python scripts\smoke.py <you>/<repo> GHSA-wf93-45jw-7689
```

**Linux / macOS (bash):**
```bash
read -rs GITHUB_TOKEN && export GITHUB_TOKEN
export SCGUARD_ALLOWED_REPOS=<you>/<repo>
python scripts/smoke.py <you>/<repo> GHSA-wf93-45jw-7689
```
Expected: the tool list, an enrichment for the pip advisory, a triage table for your repo,
and a **denied** call for `torvalds/linux` (not on the allowlist). Then check the audit log
(`~/.scguard/audit.jsonl`; on Windows `C:\Users\<you>\.scguard\audit.jsonl`).

**Troubleshooting the live run**

| Error | Meaning |
|---|---|
| `not on this server's allowlist` | Repo name differs from `SCGUARD_ALLOWED_REPOS` (check exact name) |
| Server exits: `invalid SCGUARD_ALLOWED_REPOS entries` | You used a URL; use `owner/repo` |
| `401` | Token invalid, expired or revoked |
| note with `404` | Token can't see the repo (repository access), or the feature has no data. GitHub says 404, not 403, for repos a token can't see |
| note with `403` | Feature not enabled, or the token lacks the alert permission |

### 4. Use it from Claude Desktop

Edit `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\claude_desktop_config.json`,
macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`), then fully restart Claude
Desktop ([MCP docs][connect-local]):

```json
{
  "mcpServers": {
    "scguard": {
      "command": "C:\\path\\to\\scguard-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "scguard"],
      "env": {
        "GITHUB_TOKEN": "github_pat_...",
        "SCGUARD_ALLOWED_REPOS": "<you>/supply-chain-lab"
      }
    }
  }
}
```
Then ask: *"Triage the security alerts in <you>/supply-chain-lab and tell me what to fix first."*
Server logs (stderr) end up in Claude Desktop's `mcp-server-scguard.log`.

## Demo script (for the interview)

1. Ask Claude to triage `supply-chain-lab` and show the P1–P4 table, with the **reason** column
   ("in CISA KEV", "EPSS 0.069 < 0.1", "severity high").
2. Ask it to triage `torvalds/linux` → denied by the allowlist; show the `denied` line in `audit.jsonl`.
3. Paste a token into a prompt and ask it to enrich it → rejected by validation; show the audit
   line with `[REDACTED]`.
4. Explain the trade-offs: why read-only, why fail-closed, why the server sanitises text (a repo
   owner controls alert text, and that text goes into the model's context).

## What was verified while building this

| Item | How |
|---|---|
| MCP Python SDK **2.3.0** API: `MCPServer` (FastMCP was renamed in v2), `@tool(annotations=…)`, `ToolError`, in-process `Client(server)`, `StdioServerParameters` | Installed from PyPI and read the package source and docstrings |
| Tools served over a **real stdio** subprocess, allowlist denial over stdio, fail-closed start (exit 2 when no allowlist) | Ran locally |
| GitHub endpoints, query parameters (`state`, `severity`, `tool_name`, `per_page` ≤ 100), fine-grained permissions, API version header `2026-03-10` | GitHub REST docs ([code scanning][gh-cs], [Dependabot][gh-dep]) |
| **Pagination differs per endpoint**: code scanning supports `page`; Dependabot alerts (API `2026-03-10`) has **no `page` parameter**, only `before`/`after` cursors, and answers **400** if `page` is sent. The server follows the `Link: rel="next"` header, which works for both | GitHub REST docs + **live check on 2026-11-04**: Dependabot `per_page` only → 200, with `page=1` → 400; code scanning with `page=1` → 200 |
| **Live run, 2026-11-04 (Windows)**: OSV, EPSS and CISA KEV enrichment returned real data (GHSA-wf93-45jw-7689 → CVE-2026-8643, fixed 26.1.2, EPSS 0.0032, not in KEV catalog 2026.11.03); allowlist denials worked over stdio | `scripts/smoke.py` against the real APIs |
| OSV `GET /v1/vulns/{id}`; response fields (`aliases`, `database_specific.severity`, `affected[].ranges[].events[].fixed`) | OSV API docs + a live response for GHSA-x84v-xcm2-53pg |
| EPSS `GET /data/v1/epss?cve=…` and response fields (`cve`, `epss`, `percentile`, `date`) | FIRST docs + a live response for CVE-2018-18074 (EPSS 0.069, 2026-11-03) |
| KEV fields (`cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse` ∈ {Known, Unknown}) | CISA's official `cisagov/kev-data` repo, catalog 2026.10.30, 1,766 entries |
| Stdio servers must not write to stdout; Claude Desktop config with `env` | modelcontextprotocol.io docs ([build server][build], [connect local servers][connect-local]) |
| Spec: servers MUST validate inputs, implement access control, rate-limit, sanitise outputs | [MCP spec, Tools][spec-tools] |
| Tests | `pytest`: **28 passed** (real MCP client session in-process, all HTTP mocked; unmocked hosts fail the test). The Dependabot mock reproduces the real 400-on-`page` behaviour; reintroducing the bug makes 5 tests fail |
| Lint / security lint | `ruff` (incl. bandit `S` rules): clean · `check-jsonschema` on workflows: valid · `zizmor`: 0 medium/high |

**Bug found in the live run and fixed:** v0.1.0 sent `page=1` to the Dependabot endpoint, so
`triage_repository` failed with `GitHub API error 400`. The original mocks accepted any parameter, so
the unit tests passed anyway. The lesson: mocks must encode the real API's constraints, not just its
response shape. Fixed in v0.1.1 (Link-header pagination, GitHub's error message now included in
errors, allowlist format checked at startup).

**Not yet verified:** a full live `triage_repository` run with the fix. Re-run step 3. In the unit tests
CVE-2026-8643 is placed **artificially** in a fake KEV feed to exercise the P1 path. It is
**not** in the real KEV catalog.

## Sources

- MCP spec, Tools: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk · v2 migration (FastMCP → MCPServer): https://py.sdk.modelcontextprotocol.io/v2/migration/
- Build an MCP server (stdio logging): https://modelcontextprotocol.io/docs/develop/build-server
- Connect local servers (Claude Desktop config): https://modelcontextprotocol.io/docs/develop/connect-local-servers
- GitHub REST, code scanning alerts: https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository
- GitHub REST, Dependabot alerts: https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository
- OSV API: https://google.github.io/osv.dev/get-v1-vulns/
- FIRST EPSS API: https://www.first.org/epss/api
- CISA KEV data: https://github.com/cisagov/kev-data

[spec-tools]: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
[gh-cs]: https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository
[gh-dep]: https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository
[build]: https://modelcontextprotocol.io/docs/develop/build-server
[connect-local]: https://modelcontextprotocol.io/docs/develop/connect-local-servers
