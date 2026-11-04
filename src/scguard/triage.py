"""Risk-based prioritisation.

Priority policy (transparent and deterministic, so results are reproducible
and explainable in an audit):

  P1  CVE is in CISA KEV (known exploited in the wild)
  P2  EPSS >= threshold (default 0.10), or severity critical
  P3  severity high
  P4  everything else

The EPSS threshold is a policy choice, not a standard; it is configurable in
Settings. Within a priority, items are ordered by EPSS (descending).
"""
from __future__ import annotations

SEVERITY_RANK = {"critical": 4, "high": 3, "error": 3, "medium": 2, "moderate": 2, "warning": 2,
                 "low": 1, "note": 1}


def _sev(s: str | None) -> int:
    return SEVERITY_RANK.get((s or "").lower(), 0)


def prioritise(item: dict, kev: dict[str, dict], epss: dict[str, dict], threshold: float) -> tuple[str, str]:
    cves = [i for i in item.get("vuln_ids", []) if i.startswith("CVE-")]
    kev_hits = [c for c in cves if c in kev]
    best_epss = max((epss[c]["epss"] for c in cves if c in epss), default=None)
    if kev_hits:
        extra = " (ransomware use: known)" if any(kev[c]["ransomware"] for c in kev_hits) else ""
        return "P1", f"{kev_hits[0]} is in CISA KEV{extra}"
    if best_epss is not None and best_epss >= threshold:
        return "P2", f"EPSS {best_epss:.3f} >= {threshold}"
    if _sev(item.get("severity")) >= 4:
        return "P2", "severity critical"
    if _sev(item.get("severity")) == 3:
        return "P3", "severity high"
    return "P4", "below priority thresholds"


def sort_key(item: dict) -> tuple:
    return (item["priority"], -(item.get("epss") or 0.0), -_sev(item.get("severity")))
