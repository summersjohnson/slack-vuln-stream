#!/usr/bin/env python3
"""Poll vulnerability feeds and post new CRITICAL/HIGH items to Slack."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).parent
STATE_FILE = ROOT / "state.json"
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL")
GH_TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
NVD_API_KEY = os.environ.get("NVD_API_KEY")
DRY_RUN = "--dry-run" in sys.argv
TEST_SLACK = "--test-slack" in sys.argv

LOOKBACK_HOURS = 4
NEWS_LOOKBACK_HOURS = 24  # CISA advisories + THN + SANS publish slowly; wider window backfills past day.
OVERLAP_MINUTES = 15
STATE_RETENTION_DAYS = 30
# Cap items posted per run to prevent flooding on the first run after a long
# outage. State dedup means subsequent runs will be small.
MAX_POSTS_PER_RUN = 25
USER_AGENT = "macmillan-vuln-stream/1.0 (security-monitoring)"

# Slack header emoji per severity tier. Tiers come from each fetcher:
#   CRITICAL  CVSS >= 9.0 (NVD, GHSA, MSRC summary if any criticals)
#   HIGH      CVSS 7.0–8.9 (NVD, GHSA, MSRC summary if no criticals)
#   KEV       CISA Known Exploited Vulnerabilities — actively exploited
#   ADVISORY  CISA Cybersecurity Advisories — gov-curated alert (no CVSS)
SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH":     ":warning:",
    "KEV":      ":fire:",
    "ADVISORY": ":mega:",
    "NEWS":     ":newspaper:",
}
# Decorations layered onto the header in slack_blocks():
#   :bell:  prepended when item came from a tracked vendor CNA (Adobe, Oracle,
#           VMware, Broadcom, CrowdStrike, Microsoft via MSRC)
VENDOR_EMOJI = ":bell:"

# NVD sourceIdentifier values for the vendor CNAs we care about.
NVD_VENDOR_ASSIGNERS = {
    "psirt@adobe.com":         "Adobe",
    "secalert_us@oracle.com":  "Oracle",
    "security@vmware.com":     "VMware",
    "psirt@broadcom.com":      "Broadcom",
    "psirt@crowdstrike.com":   "CrowdStrike",
}

# Adobe, Oracle, VMware/Broadcom, and CrowdStrike no longer publish working
# public RSS. They are all CNAs, so their advisories appear in NVD and get
# tagged via NVD_VENDOR_ASSIGNERS above.
VENDOR_FEEDS: list[dict] = []

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
# The Hacker News — all-topics feed (~5-10 articles/day).
# For a single topic, swap to: https://thehackernews.com/feeds/posts/default/-/{LABEL}
THN_FEED_URL = "https://feeds.feedburner.com/TheHackersNews"
# SANS Internet Storm Center — handler diaries + daily Stormcast (~2-4/day).
SANS_FEED_URL = "https://isc.sans.edu/rssfeed.xml"


def load_state():
    if not STATE_FILE.exists():
        return {"seen_ids": {}}
    return json.loads(STATE_FILE.read_text())


def save_state(state):
    cutoff = datetime.now(timezone.utc) - timedelta(days=STATE_RETENTION_DAYS)
    state["seen_ids"] = {
        k: v for k, v in state["seen_ids"].items()
        if datetime.fromisoformat(v) > cutoff
    }
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def mark_seen(state, ident):
    state["seen_ids"][ident] = datetime.now(timezone.utc).isoformat()


def is_seen(state, ident):
    return ident in state["seen_ids"]


def lookback_start():
    return datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS, minutes=OVERLAP_MINUTES)


def news_lookback_start():
    return datetime.now(timezone.utc) - timedelta(hours=NEWS_LOOKBACK_HOURS, minutes=OVERLAP_MINUTES)


def fetch_github():
    items = []
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    since = lookback_start().isoformat()
    for sev in ("critical", "high"):
        params = {"severity": sev, "per_page": 100, "sort": "published", "direction": "desc"}
        r = requests.get("https://api.github.com/advisories", headers=headers, params=params, timeout=30)
        r.raise_for_status()
        for adv in r.json():
            published = adv.get("published_at") or adv.get("updated_at") or ""
            if published < since:
                continue
            items.append({
                "source": "GitHub Advisory Database",
                "id": adv["ghsa_id"],
                "title": adv.get("summary") or adv["ghsa_id"],
                "severity": sev.upper(),
                "url": adv.get("html_url"),
                "published": published,
                "cve": adv.get("cve_id"),
            })
    return items


def fetch_nvd():
    items = []
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    end = datetime.now(timezone.utc)
    start = lookback_start()
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    for sev in ("CRITICAL", "HIGH"):
        params = {
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": end.strftime(fmt),
            "cvssV3Severity": sev,
            "resultsPerPage": 200,
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         headers=headers, params=params, timeout=60)
        msg = r.headers.get("message", "")
        if r.status_code == 404:
            print(f"[nvd] {sev}: 404 (message: {msg or 'none'})", file=sys.stderr)
            continue
        if r.status_code == 403:
            print(f"[nvd] {sev}: 403 forbidden — likely rate-limit or invalid API key (message: {msg or 'none'})", file=sys.stderr)
            continue
        r.raise_for_status()
        body = r.json()
        print(f"[nvd] {sev}: {body.get('totalResults', 0)} totalResults, {len(body.get('vulnerabilities', []))} returned",
              file=sys.stderr)
        for vuln in body.get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve["id"]
            descs = cve.get("descriptions", [])
            title = next((d["value"] for d in descs if d.get("lang") == "en"), cve_id)
            vendor = NVD_VENDOR_ASSIGNERS.get(cve.get("sourceIdentifier"))
            items.append({
                "source": "NVD",
                "id": cve_id,
                "title": title[:300],
                "severity": sev,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published"),
                "cve": cve_id,
                "vendor": vendor,
            })
    return items


def fetch_kev():
    items = []
    r = requests.get(KEV_FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
    r.raise_for_status()
    since_date = lookback_start().date()
    for v in r.json().get("vulnerabilities", []):
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < since_date:
            continue
        cve = v.get("cveID")
        if not cve:
            continue
        product = " ".join(p for p in (v.get("vendorProject"), v.get("product")) if p)
        name = v.get("vulnerabilityName") or v.get("shortDescription", "")
        title = (f"{product}: {name}" if product else name)[:300]
        items.append({
            "source": "CISA KEV (actively exploited)",
            "id": f"KEV:{cve}",
            "title": title,
            "severity": "KEV",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "published": v.get("dateAdded"),
            "cve": cve,
            "kev_ransomware": v.get("knownRansomwareCampaignUse") == "Known",
        })
    return items


def fetch_cve_program():
    # CVE Program (cve.org) data is mirrored into NVD with enrichment, so the
    # NVD fetch above is the canonical source. This stub stays for clarity and
    # can be extended to pull from github.com/CVEProject/cvelistV5 if needed.
    return []


def osv_enrich(cve_id):
    try:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}",
                         headers={"User-Agent": USER_AGENT}, timeout=15)
        if r.status_code != 200:
            return []
        affected = r.json().get("affected", [])
        ecos = {a.get("package", {}).get("ecosystem") for a in affected if a.get("package")}
        return sorted(e for e in ecos if e)
    except requests.RequestException:
        return []


def fetch_cisa():
    items = []
    try:
        r = requests.get(CISA_FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[warn] CISA fetch failed: {e}", file=sys.stderr)
        return items
    parsed = feedparser.parse(r.content)
    if parsed.bozo and not parsed.entries:
        print(f"[warn] CISA parse error: {parsed.get('bozo_exception')}", file=sys.stderr)
        return items
    since = news_lookback_start()
    for entry in parsed.entries:
        tm = entry.get("published_parsed") or entry.get("updated_parsed")
        if not tm:
            continue
        published = datetime(*tm[:6], tzinfo=timezone.utc)
        if published < since:
            continue
        items.append({
            "source": "CISA Cybersecurity Advisories",
            "id": entry.get("id") or entry.get("link") or entry.get("title", ""),
            "title": entry.get("title", "(untitled)")[:300],
            "severity": "ADVISORY",
            "url": entry.get("link", ""),
            "published": published.isoformat(),
            "cve": None,
        })
    return items


def fetch_hackernews():
    items = []
    try:
        r = requests.get(THN_FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[warn] HackerNews fetch failed: {e}", file=sys.stderr)
        return items
    parsed = feedparser.parse(r.content)
    if parsed.bozo and not parsed.entries:
        print(f"[warn] HackerNews parse error: {parsed.get('bozo_exception')}", file=sys.stderr)
        return items
    since = news_lookback_start()
    for entry in parsed.entries:
        tm = entry.get("published_parsed") or entry.get("updated_parsed")
        if not tm:
            continue
        published = datetime(*tm[:6], tzinfo=timezone.utc)
        if published < since:
            continue
        items.append({
            "source": "The Hacker News",
            "id": entry.get("id") or entry.get("link") or entry.get("title", ""),
            "title": entry.get("title", "(untitled)")[:300],
            "severity": "NEWS",
            "url": entry.get("link", ""),
            "published": published.isoformat(),
            "cve": None,
        })
    return items


def fetch_sans():
    items = []
    try:
        r = requests.get(SANS_FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[warn] SANS fetch failed: {e}", file=sys.stderr)
        return items
    parsed = feedparser.parse(r.content)
    if parsed.bozo and not parsed.entries:
        print(f"[warn] SANS parse error: {parsed.get('bozo_exception')}", file=sys.stderr)
        return items
    since = news_lookback_start()
    for entry in parsed.entries:
        tm = entry.get("published_parsed") or entry.get("updated_parsed")
        if not tm:
            continue
        published = datetime(*tm[:6], tzinfo=timezone.utc)
        if published < since:
            continue
        items.append({
            "source": "SANS Internet Storm Center",
            "id": entry.get("id") or entry.get("link") or entry.get("title", ""),
            "title": entry.get("title", "(untitled)")[:300],
            "severity": "NEWS",
            "url": entry.get("link", ""),
            "published": published.isoformat(),
            "cve": None,
        })
    return items


def fetch_msrc():
    # MSRC publishes monthly (Patch Tuesday) plus occasional out-of-band.
    # We post one summary per release rather than per-CVE to avoid flooding.
    items = []
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        r = requests.get(MSRC_UPDATES_URL, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[warn] MSRC updates fetch failed: {e}", file=sys.stderr)
        return items
    since = lookback_start()
    for upd in r.json().get("value", []):
        try:
            released = datetime.strptime(upd["InitialReleaseDate"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if released < since:
            continue
        cvrf_url = upd.get("CvrfUrl")
        if not cvrf_url:
            continue
        try:
            r2 = requests.get(cvrf_url, headers=headers, timeout=60)
            r2.raise_for_status()
            vulns = r2.json().get("Vulnerability", [])
        except requests.RequestException as e:
            print(f"[warn] MSRC cvrf fetch {upd.get('ID')}: {e}", file=sys.stderr)
            continue
        crit = high = 0
        for v in vulns:
            score = max((s.get("BaseScore", 0) for s in v.get("CVSSScoreSets", [])), default=0)
            if score >= 9.0:
                crit += 1
            elif score >= 7.0:
                high += 1
        if crit == 0 and high == 0:
            continue
        sev = "CRITICAL" if crit > 0 else "HIGH"
        title = f"{upd.get('DocumentTitle', upd['ID'])}: {len(vulns)} vulns ({crit} CRITICAL, {high} HIGH)"
        items.append({
            "source": "Microsoft MSRC",
            "id": f"MSRC-{upd['ID']}",
            "title": title[:300],
            "severity": sev,
            "url": f"https://msrc.microsoft.com/update-guide/releaseNote/{upd['ID']}",
            "published": upd["InitialReleaseDate"],
            "cve": None,
            "vendor": "Microsoft",
        })
    return items


def fetch_vendors():
    items = []
    since = lookback_start()
    for feed in VENDOR_FEEDS:
        try:
            parsed = feedparser.parse(feed["url"])
        except Exception as e:
            print(f"[warn] {feed['vendor']} fetch failed: {e}", file=sys.stderr)
            continue
        if parsed.bozo and not parsed.entries:
            print(f"[warn] {feed['vendor']} parse error: {parsed.get('bozo_exception')}", file=sys.stderr)
            continue
        for entry in parsed.entries:
            tm = entry.get("published_parsed") or entry.get("updated_parsed")
            if not tm:
                continue
            published = datetime(*tm[:6], tzinfo=timezone.utc)
            if published < since:
                continue
            ident = entry.get("id") or entry.get("link") or entry.get("title", "")
            items.append({
                "source": f"{feed['vendor']} Advisory",
                "id": ident,
                "title": entry.get("title", "(untitled)"),
                "severity": "VENDOR",
                "url": entry.get("link", ""),
                "published": published.isoformat(),
                "cve": None,
            })
    return items


def dedup_key(item):
    # KEV items use a distinct key so a CVE can post twice: once when the
    # advisory drops, again when CISA flags it actively exploited.
    if item["severity"] == "KEV":
        return f"kev:{item.get('cve') or item['id']}"
    return item.get("cve") or item["id"]


def dedup(items):
    by_key = {}
    priority = {"NVD": 3, "GitHub Advisory Database": 2}
    for item in items:
        key = dedup_key(item)
        existing = by_key.get(key)
        if existing is None or priority.get(item["source"], 0) > priority.get(existing["source"], 0):
            # Merge: keep vendor tag if either side has it.
            if existing and existing.get("vendor") and not item.get("vendor"):
                item["vendor"] = existing["vendor"]
            by_key[key] = item
    return list(by_key.values())


def slack_blocks(item):
    head = f"{SEVERITY_EMOJI.get(item['severity'], ':grey_question:')} {item['severity']} — {item['source']}"
    if item.get("vendor"):
        head = f"{VENDOR_EMOJI} {item['vendor']}  |  " + head
    if item.get("kev_ransomware"):
        head += "  |  ransomware"
    title_link = f"*<{item['url']}|{item['id']}>*\n{item['title']}" if item.get("url") else f"*{item['id']}*\n{item['title']}"
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": head}},
        {"type": "section", "text": {"type": "mrkdwn", "text": title_link}},
    ]
    fields = []
    if item.get("cve") and item["cve"] != item["id"]:
        fields.append({"type": "mrkdwn", "text": f"*CVE:* {item['cve']}"})
    if item.get("published"):
        fields.append({"type": "mrkdwn", "text": f"*Published:* {item['published']}"})
    if item.get("ecosystems"):
        fields.append({"type": "mrkdwn", "text": f"*Ecosystems:* {', '.join(item['ecosystems'])}"})
    if fields:
        blocks.append({"type": "section", "fields": fields})
    return blocks


def post_to_slack(item):
    payload = {
        "blocks": slack_blocks(item),
        "text": f"{item['severity']}: {item['id']} — {item['title']}",
    }
    if DRY_RUN or not SLACK_WEBHOOK:
        print(json.dumps(payload, indent=2))
        return
    r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
    print(f"[slack] {item['id']}: status={r.status_code} body={r.text!r}")
    r.raise_for_status()


def main():
    if not DRY_RUN and not SLACK_WEBHOOK:
        sys.exit("SLACK_WEBHOOK_URL is not set")
    if TEST_SLACK:
        post_to_slack({
            "source": "Pipeline Test",
            "id": "TEST-0001",
            "title": "If you see this, the Slack webhook is wired up correctly.",
            "severity": "HIGH",
            "url": "https://example.com/test",
            "published": datetime.now(timezone.utc).isoformat(),
            "cve": None,
            "vendor": "Test",
        })
        return
    state = load_state()
    raw = []
    for fetcher in (fetch_github, fetch_nvd, fetch_cve_program, fetch_vendors, fetch_kev, fetch_cisa, fetch_msrc, fetch_hackernews, fetch_sans):
        try:
            results = fetcher()
            print(f"[info] {fetcher.__name__}: {len(results)} item(s)")
            raw.extend(results)
        except Exception as e:
            print(f"[error] {fetcher.__name__}: {e}", file=sys.stderr)
    items = dedup(raw)
    new_items = []
    for item in items:
        key = dedup_key(item)
        if is_seen(state, key):
            continue
        if item.get("cve"):
            ecos = osv_enrich(item["cve"])
            if ecos:
                item["ecosystems"] = ecos
        new_items.append(item)
        mark_seen(state, key)
    print(f"[info] {len(new_items)} new item(s) to post (from {len(items)} candidates)")
    if len(new_items) > MAX_POSTS_PER_RUN:
        print(f"[info] capping at {MAX_POSTS_PER_RUN}; remainder will be marked seen and skipped")
        new_items = new_items[:MAX_POSTS_PER_RUN]
    for item in new_items:
        try:
            post_to_slack(item)
        except Exception as e:
            print(f"[error] slack post {item['id']}: {e}", file=sys.stderr)
    save_state(state)


if __name__ == "__main__":
    main()
