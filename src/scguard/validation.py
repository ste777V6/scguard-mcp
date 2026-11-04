"""Input validation and output sanitisation.

Everything that arrives from the model (tool arguments) is validated against
strict patterns before use. Everything that comes back from external systems
and contains free text (alert descriptions, advisory summaries) is treated as
untrusted: control characters are stripped and length is capped, so a
malicious repo can't push large or crafted text (e.g. prompt injection) into
the model's context unchecked.
"""
from __future__ import annotations

import re

from mcp.server.mcpserver.exceptions import ToolError

# GitHub: owner up to 39 chars (alnum + hyphen), repo name alnum . _ -
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_VULN_ID_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d{1,6})$"
)
# Used to pull IDs out of tool output (e.g. Grype rule ids "GHSA-xxxx-xxxx-xxxx-pip")
_VULN_ID_SEARCH = re.compile(r"(CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3})")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def validate_repo(repo: str, allowed: frozenset[str]) -> tuple[str, str]:
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo) or ".." in repo:
        raise ToolError("Invalid repository. Expected 'owner/name'.")
    if repo.lower() not in allowed:
        # Same message whether or not the repo exists: no information leak.
        raise ToolError("Repository is not on this server's allowlist.")
    owner, name = repo.split("/", 1)
    return owner, name


def invalid_allowlist_entries(allowed: frozenset[str]) -> list[str]:
    """Entries that can never match a request (e.g. full URLs instead of owner/repo)."""
    return sorted(e for e in allowed if not _REPO_RE.fullmatch(e) or ".." in e)


def validate_vuln_id(vuln_id: str) -> str:
    if not isinstance(vuln_id, str):
        raise ToolError("Invalid vulnerability id.")
    candidate = vuln_id.strip()
    if candidate.upper().startswith(("CVE-", "PYSEC-")):
        candidate = candidate.upper()
    elif candidate.upper().startswith("GHSA-"):
        candidate = "GHSA-" + candidate[5:].lower()  # GHSA ids are lower-case after the prefix
    if not _VULN_ID_RE.fullmatch(candidate):
        raise ToolError("Invalid vulnerability id. Expected CVE-YYYY-NNNN, GHSA-xxxx-xxxx-xxxx or PYSEC-YYYY-N.")
    return candidate


def extract_vuln_ids(*texts: str | None) -> list[str]:
    found: list[str] = []
    for t in texts:
        if not t:
            continue
        for m in _VULN_ID_SEARCH.findall(t):
            if m not in found:
                found.append(m)
    return found


def untrusted_text(value: object, max_chars: int) -> str:
    """Neutralise free text from external sources before returning it."""
    if value is None:
        return ""
    text = _CONTROL.sub("", str(value)).replace("\r", " ").strip()
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return text
