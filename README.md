# Slack Vuln Stream

Hourly automation that polls public vulnerability feeds and posts new CRITICAL / HIGH items to a dedicated Slack channel.

## Design

- **Hosting:** GitHub Actions cron (`0 * * * *`). No server, no Mac runtime — hosted at `summersjohnson/slack-vuln-stream`.
- **Language:** Python 3.12 with `requests` and `feedparser`.
- **Delivery:** Slack Incoming Webhook (Block Kit formatted messages).
- **Dedup:** `state.json` is committed back to the repo each run; old IDs prune after 30 days.
- **Lookback:** 4 hours per run with state-based dedup. The cron is hourly, but the wider window absorbs quiet periods and the dedup prevents reposts.
- **Anti-flood cap:** at most 25 messages per run.

## Sources

| Source | API | Role |
|---|---|---|
| GitHub Security Advisories | `api.github.com/advisories` | Primary feed for ecosystem-level CVEs |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | Canonical CVE source (covers CVE Program data) |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Actively-exploited-in-the-wild flag |
| OSV.dev | `api.osv.dev/v1/vulns/{id}` | Enrichment — adds affected ecosystems to CVE posts |
| Vendor CNA tagging | NVD `sourceIdentifier` field | Tags posts from Adobe, Oracle, VMware, Broadcom, CrowdStrike |

Note: those four vendors no longer publish working public RSS for security advisories. They are all CVE Numbering Authorities, so their CRITICAL / HIGH advisories appear in NVD and get a 🔔 vendor tag in the Slack header.

## Functionality

- Filters every fetched item by severity → only CRITICAL and HIGH (plus all KEV entries, which are by definition high-impact).
- Within a single run, GHSA + NVD entries for the same CVE are merged into one post (NVD wins, vendor tag preserved).
- KEV entries use a distinct dedup key, so a CVE can post twice — once when it lands in NVD/GHSA, again when CISA promotes it to "actively exploited."
- Slack message format: severity emoji (🚨 CRITICAL, ⚠️ HIGH, 🔥 KEV), 🔔 prefix when from a tagged vendor, ransomware tag when CISA flags ransomware-linked exploitation, fields for CVE ID, publication date, and affected ecosystems.

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
| `NVD_API_KEY` | no | Higher NVD rate limit; script works without it |
| `GITHUB_TOKEN` | auto | Provided by Actions; raises GHSA rate limit |

## Operational behavior

- Quiet hours produce zero posts — this is normal, not a bug.
- Each run logs per-source counts (`fetch_github: N item(s)`) and Slack response status for visibility.
- NVD's API returns 404 instead of 200/empty for narrow windows with no matching results; the script silently treats this as "no items."
- Workflow can be manually triggered via the **Actions** tab → **Run workflow** for ad-hoc testing.
- `python poller.py --test-slack` posts a single test message — useful for verifying the webhook end-to-end.
