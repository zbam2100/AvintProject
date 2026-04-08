import json
import os
import re
import tarfile
import time
from pathlib import Path
from datetime import datetime, timezone

import requests
import feedparser


# ----------------------------
# Config
# ----------------------------
OUT_DIR = Path(os.environ.get("OUT_DIR", "out"))
RUN = os.environ.get("RUN", datetime.now(timezone.utc).strftime("poc_%Y%m%d"))
BASE = OUT_DIR / RUN

DAYS_GH = int(os.environ.get("DAYS_GH", "7"))
MAX_PAGES_PER_QUERY = int(os.environ.get("MAX_PAGES_PER_QUERY", "5"))
DAYS_SECLISTS = int(os.environ.get("DAYS_SECLISTS", "30"))

GH_QUERIES = [
    "security",
    "vulnerability",
    "remote code execution",
    "RCE",
    "sql injection",
    "sqli",
    "cross-site scripting",
    "xss",
    "privilege escalation",
    "auth bypass",
]

CAT_RE = re.compile(
    r"(CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CWE-\d+)",
    re.I,
)

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]

HTML_TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


# ----------------------------
# Helpers
# ----------------------------
def redact(text: str) -> str:
    if not text:
        return ""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED_SECRET]", text)
    return text


def clean_summary(text: str) -> str:
    if not text:
        return ""
    text = HTML_TAG.sub(" ", text)
    text = WS.sub(" ", text).strip()
    return text


def write_jsonl(path: Path, records):
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def today_utc():
    return datetime.now(timezone.utc).date()


def within_days(date_str: str, days: int) -> bool:
    try:
        d = datetime.fromisoformat(date_str).date()
        return (today_utc() - d).days <= days
    except Exception:
        return True


def extract_repo_from_issue_url(html_url: str) -> str:
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/issues/\d+", html_url)
    return m.group(1) if m else ""


# ----------------------------
# Source 1: GitHub Issues
# ----------------------------
def scrape_github_issues():
    
    with open("github_token.txt", "r") as f:
        token = f.read().strip()

    if not token:
        raise SystemExit("ERROR: GITHUB_TOKEN is not set. Export a GitHub personal access token first.")

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "secbert-poc-scraper",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    cutoff_date = today_utc().fromordinal(today_utc().toordinal() - DAYS_GH).isoformat()

    seen_urls = set()
    out = []

    for q in GH_QUERIES:
        query = f'is:issue is:public created:>={cutoff_date} "{q}"'
        page = 1

        while page <= MAX_PAGES_PER_QUERY:
            url = "https://api.github.com/search/issues"
            params = {
                "q": query,
                "sort": "created",
                "order": "desc",
                "per_page": 100,
                "page": page,
            }

            resp = requests.get(url, headers=headers, params=params, timeout=30)
            time.sleep(2)
            if resp.status_code != 200:
                raise SystemExit(f"GitHub API error {resp.status_code}: {resp.text[:1000]}")

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for it in items:
                html_url = it.get("html_url", "")
                if not html_url or html_url in seen_urls:
                    continue
                seen_urls.add(html_url)

                title = it.get("title") or ""
                body = it.get("body") or ""

                if CAT_RE.search(title + "\n" + body):
                    continue

                repo = extract_repo_from_issue_url(html_url)

                out.append({
                    "source": "github_issue",
                    "repository": repo,
                    "url": html_url,
                    "published_date": (it.get("created_at") or "")[:10],
                    "title": title,
                    "summary": body,
                    "product": [repo.split("/")[-1]] if "/" in repo else [],
                    "component": [],
                    "version_strings": [],
                    "catalog_state": "uncataloged",
                    "exploit_status": "unknown",
                    "references": [html_url],
                })

            page += 1

    return out


# ----------------------------
# Source 2: ExploitDB RSS
# ----------------------------
def scrape_exploitdb():
    feed_url = "https://www.exploit-db.com/rss.xml"
    fp = feedparser.parse(feed_url)

    out = []
    for e in fp.entries:
        title = getattr(e, "title", "") or ""
        link = getattr(e, "link", "") or ""
        summary = getattr(e, "summary", "") or ""

        published = ""
        if getattr(e, "published_parsed", None):
            import datetime as dt
            published = dt.datetime(*e.published_parsed[:6]).date().isoformat()

        if CAT_RE.search(title + "\n" + summary):
            continue

        out.append({
            "source": "exploitdb_rss",
            "repository": "",
            "url": link,
            "published_date": published,
            "title": title,
            "summary": summary,
            "product": [],
            "component": [],
            "version_strings": [],
            "catalog_state": "uncataloged",
            "exploit_status": "exploit_poc",
            "references": [link] if link else [],
        })

    return out


# ----------------------------
# Source 3/4: Seclists RSS
# ----------------------------
def scrape_seclists(feed_url: str, source_name: str, days: int):
    fp = feedparser.parse(feed_url)

    out = []
    for e in fp.entries:
        title = getattr(e, "title", "") or ""
        link = getattr(e, "link", "") or ""
        summary = getattr(e, "summary", "") or ""

        published = ""
        st = getattr(e, "published_parsed", None) or getattr(e, "updated_parsed", None)
        if st:
            import datetime as dt
            published = dt.datetime(*st[:6]).date().isoformat()

        if published and not within_days(published, days):
            continue

        if CAT_RE.search(title + "\n" + summary):
            continue

        out.append({
            "source": source_name,
            "repository": "",
            "url": link,
            "published_date": published,
            "title": title,
            "summary": summary,
            "product": [],
            "component": [],
            "version_strings": [],
            "catalog_state": "uncataloged",
            "exploit_status": "advisory" if "full" in source_name or "fulldisclosure" in source_name else "unknown",
            "references": [link] if link else [],
        })

    return out


# ----------------------------
# Cleaning / merge
# ----------------------------
def clean_and_merge(all_files):
    merged = {}

    for src_name, records in all_files.items():
        cleaned = []
        for r in records:
            cleaned_record = dict(r)
            cleaned_record["title"] = redact(cleaned_record.get("title", "") or "")
            cleaned_record["summary"] = redact(clean_summary(cleaned_record.get("summary", "") or ""))
            cleaned.append(cleaned_record)

        raw_path = BASE / f"{src_name}_raw.jl"
        clean_path = BASE / f"{src_name}_raw_clean.jl"

        write_jsonl(raw_path, records)
        write_jsonl(clean_path, cleaned)

        for r in cleaned:
            url = (r.get("url") or "").strip()
            if url and url not in merged:
                merged[url] = r

    merged_list = list(merged.values())

    out_path = BASE / "secbert_poc_merged.jl"
    write_jsonl(out_path, merged_list)

    tgz_path = BASE / "secbert_poc_merged.tar.gz"
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(out_path, arcname="secbert_poc_merged.jl")

    return out_path, tgz_path, len(merged_list)


# ----------------------------
# Main
# ----------------------------
def main():
    BASE.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] RUN={RUN}")
    print(f"[INFO] BASE={BASE.resolve()}")

    all_files = {}

    print("[INFO] scraping GitHub issues...")
    all_files["gh_7d_strict"] = scrape_github_issues()

    print("[INFO] scraping ExploitDB RSS...")
    all_files["edb_rss"] = scrape_exploitdb()

    print("[INFO] scraping Seclists Full Disclosure...")
    all_files["seclists_fd_30d"] = scrape_seclists(
        "https://seclists.org/rss/fulldisclosure.rss",
        "seclists_fulldisclosure_rss",
        DAYS_SECLISTS,
    )

    print("[INFO] scraping Seclists oss-sec...")
    all_files["sl_oss_30d"] = scrape_seclists(
        "https://seclists.org/rss/oss-sec.rss",
        "seclists_oss-sec",
        DAYS_SECLISTS,
    )

    out_path, tgz_path, merged_count = clean_and_merge(all_files)

    print("=== COUNTS (raw lines) ===")
    for name, records in all_files.items():
        print(f"{name}: {len(records)}")

    print(f"TOTAL MERGED UNIQUE URLS: {merged_count}")

    print("=== FINAL FILES (ABSOLUTE PATHS) ===")
    print(str(out_path.resolve()))
    print(str(tgz_path.resolve()))


if __name__ == "__main__":
    main()
