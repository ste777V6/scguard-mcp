"""Live smoke test: starts the server over stdio (exactly as Claude Desktop would)
and runs the three tools against a real repository and the real APIs.

Usage:
    export GITHUB_TOKEN=github_pat_...            # fine-grained, read-only (see README)
    export SCGUARD_ALLOWED_REPOS=<you>/supply-chain-lab
    python scripts/smoke.py <you>/supply-chain-lab [CVE-or-GHSA-id]
"""
import asyncio
import json
import os
import sys

from mcp import Client, StdioServerParameters


async def main(repo: str, vuln_id: str) -> None:
    params = StdioServerParameters(command=sys.executable, args=["-m", "scguard"], env=dict(os.environ))
    async with Client(params) as c:
        print("tools:", [t.name for t in (await c.list_tools()).tools])

        r = await c.call_tool("enrich_vulnerability", {"vuln_id": vuln_id})
        print("\n# enrich_vulnerability", "(ERROR)" if r.is_error else "")
        print(json.dumps(r.structured_content, indent=2) if not r.is_error else r.content[0].text)

        r = await c.call_tool("triage_repository", {"repo": repo, "max_items": 30})
        print("\n# triage_repository", "(ERROR)" if r.is_error else "")
        print(r.structured_content["markdown"] if not r.is_error else r.content[0].text)
        if not r.is_error and r.structured_content["notes"]:
            print("notes:", r.structured_content["notes"])

        r = await c.call_tool("list_security_alerts", {"repo": "torvalds/linux"})
        print("\n# allowlist check (should be denied):", r.content[0].text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "GHSA-x84v-xcm2-53pg"))
