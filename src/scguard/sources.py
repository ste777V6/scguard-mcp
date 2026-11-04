"""Data sources: GitHub alerts (code scanning, Dependabot) and enrichment
(OSV, FIRST EPSS, CISA KEV). All calls are read-only GETs through SafeHttp.

API references (verified 2026-11-03):
- Code scanning alerts: GET /repos/{owner}/{repo}/code-scanning/alerts
  fine-grained permission "Code scanning alerts: read"
- Dependabot alerts:   GET /repos/{owner}/{repo}/dependabot/alerts
  fine-grained permission "Dependabot alerts: read"
- OSV:  GET https://api.osv.dev/v1/vulns/{id}
- EPSS: GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2
- KEV:  CISA JSON feed (fields: cveID, dateAdded, dueDate, knownRansomwareCampaignUse, ...)
"""
from __future__ import annotations

import re
import time
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

from .config import Settings
from .http import GITHUB_API, SafeHttp
from .validation import extract_vuln_ids, untrusted_text

PER_PAGE = 100  # API maximum for both alert endpoints
MAX_PAGES = 20
_LINK_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def _github_message(data: Any) -> str:
    """GitHub's own error message, sanitised (it can echo request data)."""
    if isinstance(data, dict) and data.get("message"):
        return ": " + untrusted_text(data["message"], 200)
    return ""


async def _paginate(http: SafeHttp, url: str, params: dict[str, Any], limit: int) -> tuple[list[dict], str | None]:
    """Fetch a GitHub list endpoint up to `limit` items, following the Link header.

    Following rel="next" works for both styles GitHub uses: page-number
    pagination (code scanning) and cursor pagination with before/after
    (Dependabot alerts, which has no `page` parameter and returns 400 if sent one).
    Returns (items, note); note explains non-fatal conditions.
    """
    items: list[dict] = []
    next_url: str | None = url
    next_params: dict[str, Any] | None = {**params, "per_page": PER_PAGE}
    pages = 0
    while next_url and len(items) < limit and pages < MAX_PAGES:
        res = await http.get_json(next_url, next_params)
        pages += 1
        if res.status in (403, 404):
            # 403: feature not enabled / token lacks permission; 404: no analysis, or repo not
            # visible to the token (GitHub answers 404, not 403, to avoid revealing private repos).
            return items, (f"GitHub returned {res.status}{_github_message(res.data)} "
                           "(feature not enabled, no data yet, or token lacks permission/repo access).")
        if res.status == 401:
            raise ToolError("GitHub rejected the token (401: invalid, expired or revoked). Check GITHUB_TOKEN.")
        if res.status >= 400:
            raise ToolError(f"GitHub API error {res.status}{_github_message(res.data)}")
        items.extend(res.data or [])
        m = _LINK_NEXT.search(res.headers.get("link", ""))
        # The next URL already carries all query parameters; the egress check in
        # SafeHttp still applies to it.
        next_url, next_params = (m.group(1), None) if m else (None, None)
    return items[:limit], None


def _norm_code_scanning(a: dict, s: Settings) -> dict:
    rule = a.get("rule") or {}
    tool = (a.get("tool") or {}).get("name")
    loc = ((a.get("most_recent_instance") or {}).get("location") or {}).get("path")
    return {
        "source": "code_scanning",
        "tool": untrusted_text(tool, 50),
        "number": a.get("number"),
        "rule_id": untrusted_text(rule.get("id"), 120),
        "title": untrusted_text(rule.get("description") or rule.get("name"), s.max_text_chars),
        # security_severity_level is set for security rules (CodeQL, SARIF with security-severity);
        # fall back to the generic rule severity otherwise.
        "severity": (rule.get("security_severity_level") or rule.get("severity") or "unknown"),
        "location": untrusted_text(loc, 200),
        "vuln_ids": extract_vuln_ids(rule.get("id"), rule.get("description"), rule.get("name")),
        "fixed_version": None,
        "url": a.get("html_url"),
    }


def _norm_dependabot(a: dict, s: Settings) -> dict:
    adv = a.get("security_advisory") or {}
    dep = a.get("dependency") or {}
    pkg = dep.get("package") or {}
    vuln = a.get("security_vulnerability") or {}
    ids = [i for i in (adv.get("cve_id"), adv.get("ghsa_id")) if i]
    return {
        "source": "dependabot",
        "tool": "dependabot",
        "number": a.get("number"),
        "rule_id": adv.get("ghsa_id"),
        "title": untrusted_text(adv.get("summary"), s.max_text_chars),
        "severity": adv.get("severity") or vuln.get("severity") or "unknown",
        "location": untrusted_text(dep.get("manifest_path"), 200),
        "package": untrusted_text(f"{pkg.get('ecosystem', '')}:{pkg.get('name', '')}", 120),
        "vuln_ids": ids,
        "fixed_version": ((vuln.get("first_patched_version") or {}).get("identifier")),
        "url": a.get("html_url"),
    }


async def list_code_scanning(http: SafeHttp, s: Settings, owner: str, repo: str,
                             severity: str | None, tool_name: str | None) -> tuple[list[dict], str | None]:
    params: dict[str, Any] = {"state": "open"}
    if severity:
        params["severity"] = severity
    if tool_name:
        params["tool_name"] = tool_name
    raw, note = await _paginate(http, f"{GITHUB_API}/repos/{owner}/{repo}/code-scanning/alerts",
                                params, s.max_alerts_per_source)
    return [_norm_code_scanning(a, s) for a in raw], note


async def list_dependabot(http: SafeHttp, s: Settings, owner: str, repo: str,
                          severity: str | None) -> tuple[list[dict], str | None]:
    params: dict[str, Any] = {"state": "open"}
    if severity:
        params["severity"] = severity
    raw, note = await _paginate(http, f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts",
                                params, s.max_alerts_per_source)
    return [_norm_dependabot(a, s) for a in raw], note


async def osv_lookup(http: SafeHttp, s: Settings, vuln_id: str) -> dict | None:
    res = await http.get_json(f"https://api.osv.dev/v1/vulns/{vuln_id}")
    if res.status == 404:
        return None
    if res.status >= 400:
        raise ToolError(f"OSV API error {res.status}.")
    d = res.data or {}
    fixed: list[str] = []
    for aff in d.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(str(ev["fixed"]))
    return {
        "id": d.get("id"),
        "aliases": [a for a in (d.get("aliases") or []) if isinstance(a, str)][:20],
        "summary": untrusted_text(d.get("summary"), s.max_text_chars),
        "severity_label": (d.get("database_specific") or {}).get("severity"),
        "cvss": [x.get("score") for x in (d.get("severity") or []) if isinstance(x, dict)][:4],
        "fixed_versions": fixed[:10],
        "published": d.get("published"),
    }


async def epss_scores(http: SafeHttp, cves: list[str]) -> dict[str, dict]:
    if not cves:
        return {}
    out: dict[str, dict] = {}
    # Batch in chunks to keep URLs short.
    for i in range(0, len(cves), 50):
        chunk = cves[i:i + 50]
        res = await http.get_json("https://api.first.org/data/v1/epss", {"cve": ",".join(chunk)})
        if res.status >= 400:
            raise ToolError(f"EPSS API error {res.status}.")
        for row in (res.data or {}).get("data") or []:
            try:
                out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                   "date": row.get("date")}
            except (KeyError, TypeError, ValueError):
                continue
    return out


class KevCache:
    """In-memory cache of the CISA KEV catalog (refreshed after TTL)."""

    def __init__(self) -> None:
        self._data: dict[str, dict] | None = None
        self._version: str | None = None
        self._loaded_at = 0.0

    async def get(self, http: SafeHttp, s: Settings) -> tuple[dict[str, dict], str | None]:
        if self._data is None or time.monotonic() - self._loaded_at > s.kev_cache_ttl_s:
            res = await http.get_json(s.kev_url)
            if res.status >= 400:
                raise ToolError(f"KEV feed error {res.status}.")
            doc = res.data or {}
            self._data = {
                v["cveID"]: {
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                }
                for v in doc.get("vulnerabilities") or []
                if isinstance(v, dict) and "cveID" in v
            }
            self._version = doc.get("catalogVersion")
            self._loaded_at = time.monotonic()
        return self._data, self._version
