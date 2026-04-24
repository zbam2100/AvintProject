import json
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API_KEY = None  # put your NVD API key here if you have one
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TARGET = 250
results = []
seen_descriptions = set()

session = requests.Session()
retry = Retry(
    total=5,
    backoff_factor=2,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
)
session.mount("https://", HTTPAdapter(max_retries=retry))

headers = {"User-Agent": "nvd-testsetgen/1.0"}
if API_KEY:
    headers["apiKey"] = API_KEY

start_index = 0
results_per_page = 2000  # max allowed by NVD

while len(results) < TARGET:
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    response = session.get(URL, params=params, headers=headers, timeout=60)

    if response.status_code != 200:
        print("HTTP status:", response.status_code)
        print("Message header:", response.headers.get("message"))
        print("Body preview:", response.text[:1000])
        response.raise_for_status()

    if not response.text.strip():
        raise RuntimeError("Empty response body from API")

    data = response.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        break

    for item in vulns:
        cve = item.get("cve", {})

        # Get English description
        description = None
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = " ".join(d.get("value", "").split())
                break

        if not description:
            continue

        # Deduplicate by description
        if description in seen_descriptions:
            continue

        metrics = cve.get("metrics", {})
        base_score = None

        if metrics.get("cvssMetricV31"):
            base_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif metrics.get("cvssMetricV30"):
            base_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif metrics.get("cvssMetricV2"):
            base_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        if base_score is None:
            continue

        results.append({
            "risk_score": round(float(base_score) * 10, 1),
            "description": description
        })
        seen_descriptions.add(description)

        if len(results) >= TARGET:
            break

    start_index += results_per_page
    time.sleep(6 if not API_KEY else 1)

with open("vulnerabilities_250.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"Wrote {len(results)} entries to vulnerabilities_250.json")
