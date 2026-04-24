import json
import math
import time
import requests
from pathlib import Path
from collections import defaultdict

OUTPUT_FILE = Path("/home/avint/cve_reference_300.json")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
TARGET_SIZE = 300

BANDS = [
    (0, 9),
    (10, 19),
    (20, 29),
    (30, 39),
    (40, 49),
    (50, 59),
    (60, 69),
    (70, 79),
    (80, 89),
    (90, 100),
]


def get_cvss_base_score(cve_obj):
    metrics = cve_obj.get("metrics", {})

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return float(score)

    return None


def get_description(cve_obj):
    for item in cve_obj.get("descriptions", []):
        if item.get("lang") == "en":
            text = item.get("value", "").strip()
            if text:
                return text
    return None


def get_severity(cve_obj):
    metrics = cve_obj.get("metrics", {})

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            sev = metric_list[0].get("cvssData", {}).get("baseSeverity")
            if sev:
                return str(sev).lower()

    return ""


def score_to_band(score):
    for lo, hi in BANDS:
        if lo <= score <= hi:
            return f"{lo:02d}-{hi:02d}"
    return "unknown"


def fetch_batch(start_index):
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    r = requests.get(BASE_URL, params=params, timeout=120)
    r.raise_for_status()
    return r.json()


def build_dataset(max_pages=8):
    seen_ids = set()
    buckets = defaultdict(list)

    start_index = 0
    total_results = None

    for page in range(max_pages):
        print(f"Fetching page {page + 1}...")

        data = fetch_batch(start_index)

        if total_results is None:
            total_results = data.get("totalResults", 0)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for wrapper in vulns:
            cve = wrapper.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id or cve_id in seen_ids:
                continue

            description = get_description(cve)
            base_score = get_cvss_base_score(cve)

            if not description or base_score is None:
                continue

            risk_score = int(round(base_score * 10))
            risk_score = max(0, min(100, risk_score))

            severity = get_severity(cve)

            text = f"""
REFERENCE CVE CASE (for calibration only)
cve_id: {cve_id}
description: {description}
severity: {severity}
risk_score: {risk_score}
""".strip()

            chunk = {
                "text": text,
                "record_type": "cve_reference",
                "cve_id": cve_id,
                "risk_score": risk_score,
                "severity": severity,
                "title": cve_id
            }

            band = score_to_band(risk_score)
            buckets[band].append(chunk)

            seen_ids.add(cve_id)

        start_index += RESULTS_PER_PAGE

        if start_index >= total_results:
            break

        time.sleep(1.5)

    return buckets


def select_balanced(buckets):
    ordered_bands = [f"{lo:02d}-{hi:02d}" for lo, hi in BANDS]
    per_band = math.ceil(TARGET_SIZE / len(ordered_bands))

    selected = []

    for band in ordered_bands:
        selected.extend(buckets.get(band, [])[:per_band])

    if len(selected) < TARGET_SIZE:
        used_ids = {x["cve_id"] for x in selected}
        leftovers = []

        for band in ordered_bands:
            for item in buckets.get(band, []):
                if item["cve_id"] not in used_ids:
                    leftovers.append(item)

        selected.extend(leftovers[:TARGET_SIZE - len(selected)])

    return selected[:TARGET_SIZE]


def print_distribution(items):
    counts = defaultdict(int)

    for item in items:
        score = item["risk_score"]
        band = score_to_band(score)
        counts[band] += 1

    print("\nDistribution:")
    for lo, hi in BANDS:
        band = f"{lo:02d}-{hi:02d}"
        print(f"{band}: {counts[band]}")


def main():
    buckets = build_dataset(max_pages=10)
    dataset = select_balanced(buckets)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print_distribution(dataset)
    print(f"\nSaved {len(dataset)} CVE records to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
