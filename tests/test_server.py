"""End-to-end tests through a real MCP client session (in-process transport),
with all outbound HTTP mocked by respx (unmocked hosts fail the test)."""
import pytest
from mcp import Client

from conftest import DEPENDABOT, REPO, TOKEN, audit_lines

pytestmark = pytest.mark.anyio


async def test_tools_are_listed_and_read_only(server):
    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert set(tools) == {"list_security_alerts", "enrich_vulnerability", "triage_repository"}
    for t in tools.values():
        assert t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False


async def test_list_alerts_merges_sources_and_extracts_ids(server, api):
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO})
    assert not r.is_error
    data = r.structured_content
    assert data["count"] == 3
    grype = next(a for a in data["alerts"] if a["tool"] == "Grype")
    assert grype["vuln_ids"] == ["GHSA-wf93-45jw-7689"]
    dep = next(a for a in data["alerts"] if a["source"] == "dependabot")
    assert dep["vuln_ids"] == ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"]
    assert dep["fixed_version"] == "2.20.0"


async def test_github_requests_carry_token_and_api_version(server, api):
    async with Client(server) as c:
        await c.call_tool("list_security_alerts", {"repo": REPO, "source": "dependabot", "severity": "high"})
    req = api.calls.last.request
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.headers["X-GitHub-Api-Version"] == "2026-03-10"
    assert req.url.params["state"] == "open" and req.url.params["severity"] == "high"


async def test_token_never_sent_to_third_parties(server, api):
    async with Client(server) as c:
        await c.call_tool("enrich_vulnerability", {"vuln_id": "CVE-2018-18074"})
    for call in api.calls:
        if call.request.url.host != "api.github.com":
            assert "Authorization" not in call.request.headers


async def test_repo_not_in_allowlist_is_denied_without_network(server, api, settings):
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": "someone/else"})
    assert r.is_error and "allowlist" in r.content[0].text
    assert len(api.calls) == 0
    assert audit_lines(settings)[-1]["outcome"] == "denied"


@pytest.mark.parametrize("bad", ["../etc/passwd", "owner/repo?x=1", "owner", "a/b/c", "own er/repo", "-x/y"])
async def test_malformed_repo_rejected(server, api, bad):
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": bad})
    assert r.is_error
    assert len(api.calls) == 0


@pytest.mark.parametrize("bad", ["CVE-18-1", "GHSA-xxxx", "../../v1/vulns", "CVE-2018-18074;rm -rf /", ""])
async def test_malformed_vuln_id_rejected(server, api, bad):
    async with Client(server) as c:
        r = await c.call_tool("enrich_vulnerability", {"vuln_id": bad})
    assert r.is_error
    assert len(api.calls) == 0


async def test_schema_rejects_bad_enum_and_tool_name(server, api):
    async with Client(server) as c:
        r1 = await c.call_tool("list_security_alerts", {"repo": REPO, "severity": "urgent"})
        r2 = await c.call_tool("list_security_alerts", {"repo": REPO, "tool_name": "x&state=closed"})
    assert r1.is_error and r2.is_error
    assert len(api.calls) == 0


async def test_untrusted_text_is_sanitised(server, api):
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO, "source": "code_scanning"})
    codeql = next(a for a in r.structured_content["alerts"] if a["tool"] == "CodeQL")
    assert "‮" not in codeql["title"]          # bidi override stripped
    assert len(codeql["title"]) <= 300              # length capped


async def test_enrich_combines_osv_epss_kev(server, api):
    async with Client(server) as c:
        r = await c.call_tool("enrich_vulnerability", {"vuln_id": "ghsa-wf93-45jw-7689"})
    d = r.structured_content
    assert d["id"] == "GHSA-wf93-45jw-7689"
    assert d["fixed_versions"] == ["26.1.2"]
    assert d["severity_label"] == "MODERATE"
    assert d["in_cisa_kev"] is True and d["kev_due_date"] == "2026-10-22"
    assert d["kev_catalog_version"] == "2026.10.30"


async def test_triage_priorities_and_reasons(server, api):
    async with Client(server) as c:
        r = await c.call_tool("triage_repository", {"repo": REPO})
    d = r.structured_content
    by_rule = {i["rule_id"]: i for i in d["items"]}
    pip = by_rule["GHSA-wf93-45jw-7689-pip"]
    assert pip["priority"] == "P1" and "KEV" in pip["reason"]
    assert "CVE-2026-8643" in pip["vuln_ids"] and pip["fixed_version"] == "26.1.2"
    assert by_rule["py/sql-injection"]["priority"] == "P2"   # critical, no CVE
    assert by_rule["GHSA-x84v-xcm2-53pg"]["priority"] == "P3"  # high, EPSS 0.069 < 0.1
    assert d["items"][0]["priority"] == "P1"                   # sorted
    assert d["by_priority"] == {"P1": 1, "P2": 1, "P3": 1, "P4": 0}
    assert "| P1 |" in d["markdown"]


async def test_feature_disabled_is_a_note_not_a_crash(server, api):
    from httpx import Response
    api.get(f"https://api.github.com/repos/{REPO}/code-scanning/alerts").mock(return_value=Response(403, json={}))
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO})
    assert not r.is_error
    assert r.structured_content["count"] == 1
    assert any("403" in n for n in r.structured_content["notes"])


async def test_dependabot_request_has_no_page_param(server, api):
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO, "source": "dependabot"})
    assert not r.is_error, r.content[0].text
    sent = api.calls.last.request.url.params
    assert "page" not in sent and sent["per_page"] == "100"


async def test_pagination_follows_link_header(server, api):
    from httpx import Response
    page2 = "https://api.github.com/repositories/1/dependabot/alerts?per_page=100&after=CURSOR1"
    first = [dict(DEPENDABOT[0], number=n) for n in range(1, 101)]   # a full page of 100
    second = [dict(DEPENDABOT[0], number=101)]

    def handler(request):
        if request.url.params.get("after") == "CURSOR1":
            return Response(200, json=second)
        return Response(200, json=first, headers={"Link": f'<{page2}>; rel="next"'})
    api.get(f"https://api.github.com/repos/{REPO}/dependabot/alerts").mock(side_effect=handler)
    api.get("https://api.github.com/repositories/1/dependabot/alerts").mock(side_effect=handler)
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO, "source": "dependabot"})
    assert r.structured_content["count"] == 101


async def test_github_error_message_is_surfaced(server, api):
    from httpx import Response
    api.get(f"https://api.github.com/repos/{REPO}/code-scanning/alerts").mock(
        return_value=Response(400, json={"message": "Bad request‮"}))
    async with Client(server) as c:
        r = await c.call_tool("list_security_alerts", {"repo": REPO, "source": "code_scanning"})
    assert r.is_error
    assert "400: Bad request" in r.content[0].text and "‮" not in r.content[0].text


def test_startup_rejects_url_in_allowlist(tmp_path):
    import os
    import subprocess
    import sys
    env = {**os.environ, "SCGUARD_ALLOWED_REPOS": "https://github.com/ste777V6/supply-chain/",
           "SCGUARD_AUDIT_LOG": str(tmp_path / "a.jsonl")}
    p = subprocess.run([sys.executable, "-m", "scguard"], env=env, capture_output=True, text=True,  # noqa: S603
                       timeout=30)
    assert p.returncode == 2
    assert "expected 'owner/repo'" in p.stderr


async def test_rate_limit(api, tmp_path):
    from dataclasses import replace

    from scguard.config import Settings
    from scguard.server import create_server
    s = replace(Settings(github_token=None, allowed_repos=frozenset({REPO}),
                         audit_log_path=tmp_path / "a.jsonl"), rate_limit_calls=2)
    async with Client(create_server(s)) as c:
        results = [await c.call_tool("enrich_vulnerability", {"vuln_id": "CVE-2018-18074"}) for _ in range(3)]
    assert [r.is_error for r in results] == [False, False, True]
    assert "Rate limit" in results[2].content[0].text
    assert audit_lines(s)[-1]["outcome"] == "denied"


async def test_egress_allowlist_blocks_other_hosts(settings):
    from scguard.http import EgressDenied, SafeHttp
    http = SafeHttp(settings)
    with pytest.raises(EgressDenied):
        await http.get_json("https://attacker.example/collect")
    with pytest.raises(EgressDenied):
        await http.get_json("http://api.github.com/")  # plain HTTP refused too
    await http.aclose()


async def test_audit_log_records_calls_and_never_the_token(server, api, settings):
    async with Client(server) as c:
        await c.call_tool("list_security_alerts", {"repo": REPO})
        await c.call_tool("list_security_alerts", {"repo": "evil/repo"})
        await c.call_tool("enrich_vulnerability", {"vuln_id": TOKEN})  # token pasted as input
    lines = audit_lines(settings)
    assert [ln["outcome"] for ln in lines] == ["ok", "denied", "error"]
    assert lines[0]["result_count"] == 3
    raw = settings.audit_log_path.read_text()
    assert TOKEN not in raw and "[REDACTED]" in raw
