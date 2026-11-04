
<img width="544" height="295" alt="image" src="https://github.com/user-attachments/assets/74f81614-0c64-4515-99b5-a2c53aba2b67" />

<img width="520" height="391" alt="image" src="https://github.com/user-attachments/assets/0043fad4-656d-4e1d-98df-ea9799b659e5" />


It works end to end. The server read all 30 open alerts, the same count GitHub’s Security tab showed, enriched them with real EPSS and KEV data, and ranked them. The allowlist still denies. That completes the live check that was missing.

What the result says. No alert reached P1 or P2: none is in CISA KEV, and every EPSS score is below 0.01, meaning under 1% estimated chance of exploitation in the next 30 days. So: 30 alerts, nothing urgent by exploit likelihood. That’s exactly the “reduce noise” message from the EPAM description: plain severity counts would suggest a fire, and the enrichment shows there isn’t one.

Reading the output critically, there are three weaknesses worth fixing (and worth mentioning yourself in an interview):

Duplicates. Each Grype finding appears twice, e.g. GHSA-wf93… on two rows. That fits the two copies of pip in the image (system and venv) we saw earlier. The server should group them as one vulnerability with “2 locations”, so it shows 6 issues instead of 12 rows.
Repo-hygiene findings mixed with vulnerabilities. Scorecard’s BranchProtection, CodeReview and so on are repo settings, not exploitable flaws. Their “high” isn’t comparable to a CVE’s “high”, yet they sit in P3 next to real vulnerabilities. They belong in a separate “posture” section.
Empty “Fix” column on CVE-only rows (CVE-2025-12781, CVE-2025-15366, …). The server only looks up fixed versions in OSV for GHSA alerts. These rows are probably OS packages in the Debian base image; that’s a guess, so click one alert on GitHub and check its location. If they have no fix yet, that’s also why Grype’s only-fixed gate let the build through.

Quick win on the real findings. Several GHSA rows have fixed versions like 25.3, 26.0, 26.1 and 26.2.0, which look like pip versions. If they are all pip, the “remove pip from the runtime image” change from Project 1 would close about 12 of the 30 rows in one commit. That fix plus a re-run of this triage makes a good before/after demo.

Next:

scguard is connected: its three tools just appeared in this conversation, through your Claude Desktop. So I can run the three test prompts myself, here.

It’s working end to end. I ran the three test prompts through your Claude Desktop connection, so these are real calls on your machine with your token, and they’re recorded in your audit log:

Test	Result
Triage ste777V6/supply-chain	✅ 30 alerts: P1 0, P2 0, P3 5, P4 25. Same as the smoke test
Enrich CVE-2018-18074	✅ EPSS 0.069, in the 94th percentile, not in CISA KEV
Triage torvalds/linux	✅ Denied by the allowlist

This live run found a new bug, the 4th weakness. Enriching by CVE id returned bad data:

fixed_versions holds git commit hashes (bd840450…) instead of 2.20.0,
the summary and severity label are empty.

By GHSA id, the same vulnerability comes back correct (we saw 2.20.0 earlier). My understanding of the cause, still to be checked: OSV’s CVE record describes the fix as upstream git commits, and my code takes every “fixed” event without checking the range type. The fix would be to use only package-version ranges, and to follow the GHSA alias when the CVE record has none.

A point for the interview. CVE-2018-18074 scores higher than 94% of all CVEs for exploit likelihood, yet it stays below my P2 threshold of 0.10. That shows the threshold is a policy choice, and a debatable one: some teams use a percentile cut-off instead (e.g. top 5%). Being able to explain this trade-off matters more than the exact number.

What’s next:

Rotate the token, if you haven’t yet. The one in your config was exposed in this chat. Put the new one in the config, quit Claude Desktop completely and reopen it.
scguard v0.1.2 to fix the four weaknesses found in live use:
group duplicate findings,
separate Scorecard posture findings from vulnerabilities,
look up fixes for CVE-only alerts,
correct the version ranges when enriching by CVE (the bug above).
The Project 1 fix: remove pip from the image. Most of the GHSA rows above are pip advisories. After the change, a re-triage would show the before/after effect.
Project 3, the Kubernetes admission policy, when you have time to run it.

I’d do 2, then 3: fix the tool first, then use it to measure the real fix. Shall I start on v0.1.2?



