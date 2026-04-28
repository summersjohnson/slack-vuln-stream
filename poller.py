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

LOOKBACK_HOURS = 1
OVERLAP_MINUTES = 15
STATE_RETENTION_DAYS = 30

VENDOR_FEEDS = [
    {"vendor": "Adobe",       "url": "https://helpx.adobe.com/security/security-bulletin.rss"},
    {"vendor": "Oracle",      "url": "https://www.oracle.com/security-alerts/rss.xml"},
    {"vendor": "VMware",      "url": "https://support.broadcom.com/web/ecx/security-advisory/-/security-advisories.atom"},
    {"vendor": "CrowdStrike", "url": "https://www.crowdstrike.com/en-us/blog/category/cybersecurity/feed/"},
]


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


def fetch_github():
    items = []
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
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
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
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
        r.raise_for_status()
        for vuln in r.json().get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve["id"]
            descs = cve.get("descriptions", [])
            title = next((d["value"] for d in descs if d.get("lang") == "en"), cve_id)
            items.append({
                "source": "NVD",
                "id": cve_id,
                "title": title[:300],
                "severity": sev,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published"),
                "cve": cve_id,
            })
    return items


def fetch_cve_program():
    # CVE Program (cve.org) data is mirrored into NVD with enrichment, so the
    # NVD fetch above is the canonical source. This stub stays for clarity and
    # can be extended to pull from github.com/CVEProject/cvelistV5 if needed.
    return []


def osv_enrich(cve_id):
    try:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=15)
        if r.status_code != 200:
            return []
        affected = r.json().get("affected", [])
        ecos = {a.get("package", {}).get("ecosystem") for a in affected if a.get("package")}
        return sorted(e for e in ecos if e)
    except requests.RequestException:
        return []


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


def dedup(items):
    by_key = {}
    priority = {"NVD": 3, "GitHub Advisory Database": 2}
    for item in items:
        key = item.get("cve") or item["id"]
        existing = by_key.get(key)
        if existing is None or priority.get(item["source"], 0) > priority.get(existing["source"], 0):
            by_key[key] = item
    return list(by_key.values())


def slack_blocks(item):
    emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:", "VENDOR": ":shield:"}
    head = f"{emoji.get(item['severity'], ':grey_question:')} {item['severity']} — {item['source']}"
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
    r.raise_for_status()


def main():
    if not DRY_RUN and not SLACK_WEBHOOK:
        sys.exit("SLACK_WEBHOOK_URL is not set")
    state = load_state()
    raw = []
    for fetcher in (fetch_github, fetch_nvd, fetch_cve_program, fetch_vendors):
        try:
            raw.extend(fetcher())
        except Exception as e:
            print(f"[error] {fetcher.__name__}: {e}", file=sys.stderr)
    items = dedup(raw)
    new_items = []
    for item in items:
        key = item.get("cve") or item["id"]
        if is_seen(state, key):
            continue
        if item.get("cve"):
            ecos = osv_enrich(item["cve"])
            if ecos:
                item["ecosystems"] = ecos
        new_items.append(item)
        mark_seen(state, key)
    print(f"[info] {len(new_items)} new item(s) to post (from {len(items)} candidates)")
    for item in new_items:
        try:
            post_to_slack(item)
        except Exception as e:
            print(f"[error] slack post {item['id']}: {e}", file=sys.stderr)
    save_state(state)


if __name__ == "__main__":
    main()
