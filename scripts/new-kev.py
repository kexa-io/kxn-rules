#!/usr/bin/env python3
"""List the CISA KEV entries this repository has no rule for yet.

KEV (Known Exploited Vulnerabilities) is CISA's catalogue of CVEs exploited in
the wild. For each recent entry that no pack mentions and that
cve/skipped.txt does not list, print one JSON line: the KEV entry plus the NVD
description, affected version ranges (CPE matches) and references.

Usage: new-kev.py [--days N] [--max N] [--cve CVE-ID ...]
"""

import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import date, timedelta
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
ROOT = Path(__file__).resolve().parent.parent


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "kxn-rules-cve-pipeline"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def covered() -> set[str]:
    """CVE ids some pack already names, or that were looked at and skipped."""
    ids: set[str] = set()
    pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    for f in ROOT.rglob("*.toml"):
        ids.update(m.upper() for m in pattern.findall(f.read_text(errors="ignore")))
    skipped = ROOT / "cve" / "skipped.txt"
    if skipped.exists():
        ids.update(m.upper() for m in pattern.findall(skipped.read_text()))
    return ids


def nvd(cve: str) -> dict:
    try:
        vulns = fetch(NVD_URL.format(cve)).get("vulnerabilities") or []
    except Exception as e:  # NVD is often slow: the KEV entry alone still helps
        return {"nvd_error": str(e)}
    if not vulns:
        return {"nvd_error": "not in NVD yet"}
    c = vulns[0]["cve"]
    ranges = []
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    ranges.append({k: v for k, v in m.items() if k != "matchCriteriaId"})
    return {
        "description": next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), ""),
        "affected": ranges[:40],
        "references": [r["url"] for r in c.get("references", [])][:15],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=3, help="KEV entries added in the last N days")
    ap.add_argument("--max", type=int, default=5, help="at most N CVEs per run")
    ap.add_argument("--cve", nargs="*", default=[], help="these CVEs instead of the recent ones")
    args = ap.parse_args()

    kev = fetch(KEV_URL)["vulnerabilities"]
    done = covered()
    if args.cve:
        wanted = {c.upper() for c in args.cve}
        todo = [v for v in kev if v["cveID"] in wanted]
        missing = wanted - {v["cveID"] for v in todo}
        todo += [{"cveID": c, "note": "not in the KEV catalogue"} for c in sorted(missing)]
    else:
        since = (date.today() - timedelta(days=args.days)).isoformat()
        todo = [v for v in kev if v["dateAdded"] >= since and v["cveID"] not in done]
        todo.sort(key=lambda v: v["dateAdded"], reverse=True)
    todo = todo[: args.max]

    for i, entry in enumerate(todo):
        if i:
            time.sleep(7)  # NVD allows 5 requests per 30 s without an API key
        print(json.dumps({**entry, **nvd(entry["cveID"])}))
    print(f"{len(todo)} CVE(s) to process", file=sys.stderr)


if __name__ == "__main__":
    main()
