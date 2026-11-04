"""Read-only HTTP client with an egress allowlist.

- Only GET is exposed: the server cannot modify anything, even if a model is
  tricked into trying.
- Every request's host is checked against the allowlist BEFORE sending, and
  redirects are not followed (a redirect could leave the allowlist).
- The GitHub token is attached only to api.github.com requests.
- Response size and time are capped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from .config import Settings

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"


class EgressDenied(ToolError):
    pass


@dataclass
class HttpResult:
    status: int
    data: Any
    headers: httpx.Headers


class SafeHttp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._s = settings
        self._client = httpx.AsyncClient(
            timeout=settings.http_timeout_s,
            follow_redirects=False,
            headers={"User-Agent": "scguard-mcp"},
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_host(self, url: str) -> httpx.URL:
        u = httpx.URL(url)
        if u.scheme != "https" or u.host not in self._s.egress_allowlist:
            raise EgressDenied(f"Egress to '{u.host}' is not allowed by policy.")
        return u

    async def get_json(self, url: str, params: dict[str, Any] | None = None) -> HttpResult:
        u = self._check_host(url)
        headers = {}
        if u.host == "api.github.com":
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = GITHUB_API_VERSION
            if self._s.github_token:
                headers["Authorization"] = f"Bearer {self._s.github_token}"
        try:
            async with self._client.stream("GET", u, params=params, headers=headers) as resp:
                if 300 <= resp.status_code < 400:
                    raise ToolError(f"Unexpected redirect from {u.host}; not followed.")
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._s.max_response_bytes:
                        raise ToolError(f"Response from {u.host} exceeded size limit.")
                status, resp_headers = resp.status_code, resp.headers
        except httpx.TimeoutException as exc:
            raise ToolError(f"Timed out calling {u.host}.") from exc
        except httpx.TransportError as exc:
            raise ToolError(f"Network error calling {u.host}.") from exc
        data = None
        if body:
            try:
                data = json.loads(body)
            except ValueError as exc:
                if status < 400:
                    raise ToolError(f"Invalid JSON from {u.host}.") from exc
                # Error bodies that aren't JSON are simply ignored.
        return HttpResult(status=status, data=data, headers=resp_headers)
