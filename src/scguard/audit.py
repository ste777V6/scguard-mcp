"""Append-only JSONL audit log of every tool call.

Written to a file (never stdout: with the stdio transport, stdout carries the
JSON-RPC stream). Secrets are redacted before anything is written.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# GitHub token formats: classic (ghp_), OAuth (gho_), user-to-server (ghu_),
# server-to-server (ghs_), refresh (ghr_), fine-grained PAT (github_pat_).
_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, str):
        out = _TOKEN_RE.sub("[REDACTED]", value)
        for s in secrets:
            if s:
                out = out.replace(s, "[REDACTED]")
        return out
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    return value


class AuditLog:
    def __init__(self, path: Path, secrets: tuple[str, ...] = ()):
        self._path = path
        self._secrets = secrets
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, *, tool: str, args: dict[str, Any], outcome: str, duration_ms: int,
               detail: str | None = None, result_count: int | None = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": tool,
            "args": args,
            "outcome": outcome,  # ok | denied | error
            "duration_ms": duration_ms,
        }
        if result_count is not None:
            entry["result_count"] = result_count
        if detail:
            entry["detail"] = detail[:500]
        line = json.dumps(redact(entry, self._secrets), ensure_ascii=False)
        with self._lock, self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
