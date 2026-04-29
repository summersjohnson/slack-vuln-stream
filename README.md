# Slack Vuln Stream

Hourly automation that polls public vulnerability feeds and posts new items to a dedicated Slack channel — CRITICAL / HIGH CVEs, actively-exploited vulnerabilities (CISA KEV), government cybersecurity advisories (CISA), and Microsoft Patch Tuesday roll-ups.

## Design

- **Hosting:** GitHub Actions cron (`0 * * * *`). No server, no Mac runtime — hosted at `summersjohnson/slack-vuln-stream`.
- **Language:** Python 3.12 with `requests` and `feedparser`.
- **Delivery:** Slack Incoming Webhook (Block Kit formatted messages).
- **Dedup:** `state.json` is committed back to the repo each run; old IDs prune after 30 days.
- **Lookback:** 4 hours for vuln feeds (NVD, GHSA, KEV) and 24 hours for slower news/advisory feeds (CISA Advisories, The Hacker News, SANS ISC). State-based dedup prevents reposts.
- **Anti-flood cap:** at most 25 messages per run.

## Sources

| Source | API | Role |
|---|---|---|
| GitHub Security Advisories | `api.github.com/advisories` | Primary feed for ecosystem-level CVEs |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | Canonical CVE source (covers CVE Program data) |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Actively-exploited-in-the-wild flag |
| CISA Cybersecurity Advisories | `cisa.gov/cybersecurity-advisories/all.xml` | Government-curated alerts (joint FBI/NSA bulletins, ICS, etc.) |
| Microsoft MSRC | `api.msrc.microsoft.com/cvrf/v3.0/updates` | One summary per Patch Tuesday release (vuln counts) |
| The Hacker News | `feeds.feedburner.com/TheHackersNews` | All-topics cybersecurity news feed (~5-10 articles/day) |
| SANS Internet Storm Center | `isc.sans.edu/rssfeed.xml` | Handler diaries + daily Stormcast (~2-4 articles/day) |
| AlienVault OTX | `otx.alienvault.com/api/v1/pulses/subscribed` | Subscribed threat-intel pulses (IoCs, adversaries, malware families) |
| OSV.dev | `api.osv.dev/v1/vulns/{id}` | Enrichment — adds affected ecosystems to CVE posts |
| Vendor CNA tagging | NVD `sourceIdentifier` field | Tags posts from Adobe, Oracle, VMware, Broadcom, CrowdStrike |

Note: those four vendors no longer publish working public RSS for security advisories. They are all CVE Numbering Authorities, so their CRITICAL / HIGH advisories appear in NVD and get a 🔔 vendor tag in the Slack header. Microsoft is tagged separately via the MSRC source.

## Functionality

- **Severity filter:** CVE-based sources (NVD, GHSA) post only CRITICAL and HIGH. KEV posts every entry (all KEV is by definition high-impact). CISA Cybersecurity Advisories post every entry (gov-curated signal). MSRC posts one summary per release with embedded counts.
- **Within-run dedup:** GHSA + NVD entries for the same CVE merge into one post (NVD wins, vendor tag preserved).
- **Cross-run dedup:** KEV entries use a distinct dedup key, so a CVE can post twice — once when it lands in NVD/GHSA, again when CISA promotes it to "actively exploited."
- **Slack header:** `[🔔 Vendor | ] <severity-emoji> <SEVERITY> — <Source> [ | ransomware]`
- **Severity emoji:** 🚨 CRITICAL · ⚠️ HIGH · 🔥 KEV · 📣 ADVISORY (CISA general) · 📰 NEWS (The Hacker News, SANS) · 🕵️ INTEL (AlienVault OTX)
- **Body fields:** CVE ID, publication date, affected ecosystems (from OSV enrichment)

## Repo structure

```
poller.py                       Main script
requirements.txt                requests + feedparser
state.json                      Dedup state (auto-managed)
.github/workflows/poll-vulns.yml  Hourly cron workflow
.gitignore
```

## Secrets (GitHub repo)

| Name | Required | Purpose |
|---|---|---|
| `SLACK_WEBHOOK_URL` | yes | Incoming Webhook URL for the channel |
| `OTX_API_KEY` | no | Enables AlienVault OTX subscribed pulses; skipped silently if absent |
| `NVD_API_KEY` | no | Higher NVD rate limit; script works without it |
| `GITHUB_TOKEN` | auto | Provided by Actions; raises GHSA rate limit |

## Operational behavior

- Quiet hours produce zero posts — this is normal, not a bug.
- Each run logs per-source counts (`fetch_github: N item(s)`) and Slack response status for visibility.
- NVD's API returns 404 instead of 200/empty for narrow windows with no matching results; the script silently treats this as "no items."
- Workflow can be manually triggered via the **Actions** tab → **Run workflow** for ad-hoc testing.
- `python poller.py --test-slack` posts a single test message — useful for verifying the webhook end-to-end.
