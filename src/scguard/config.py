"""Runtime configuration, loaded from environment variables only.

Fail-closed: if no repository allowlist is configured, the server refuses to
touch any repository.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Every host this server may contact. Anything else is refused before a socket opens.
DEFAULT_EGRESS_ALLOWLIST = frozenset(
    {
        "api.github.com",
        "api.osv.dev",
        "api.first.org",
        "www.cisa.gov",
        "raw.githubusercontent.com",  # CISA's official mirror: github.com/cisagov/kev-data
    }
)


@dataclass(frozen=True)
class Settings:
    github_token: str | None
    allowed_repos: frozenset[str]  # lower-case "owner/repo"
    audit_log_path: Path
    kev_url: str = DEFAULT_KEV_URL
    egress_allowlist: frozenset[str] = field(default=DEFAULT_EGRESS_ALLOWLIST)
    http_timeout_s: float = 15.0
    max_response_bytes: int = 20 * 1024 * 1024  # KEV feed is ~1.5 MB
    max_alerts_per_source: int = 200
    max_text_chars: int = 300  # cap for untrusted free text returned to the model
    kev_cache_ttl_s: int = 6 * 3600
    epss_priority_threshold: float = 0.1  # policy choice, see README
    rate_limit_calls: int = 30  # max tool calls ...
    rate_limit_window_s: float = 60.0  # ... per sliding window (MCP spec: servers MUST rate limit)

    @classmethod
    def from_env(cls) -> "Settings":
        repos = os.environ.get("SCGUARD_ALLOWED_REPOS", "")
        allowed = frozenset(r.strip().lower() for r in repos.split(",") if r.strip())
        audit = os.environ.get("SCGUARD_AUDIT_LOG") or str(Path.home() / ".scguard" / "audit.jsonl")
        return cls(
            github_token=os.environ.get("GITHUB_TOKEN") or None,
            allowed_repos=allowed,
            audit_log_path=Path(audit),
            kev_url=os.environ.get("SCGUARD_KEV_URL", DEFAULT_KEV_URL),
        )
