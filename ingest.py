import json
from datetime import datetime


def load_risk_taxonomy(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def risk_taxonomy_to_text(taxonomy):
    return json.dumps(taxonomy, indent=2, ensure_ascii=False)


def load_jl_file(file_path):
    records = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            records.append({
                "source_file": file_path.name,
                "line_number": line_number,
                "data": data
            })

    return records


def load_multiple_files(file_paths):
    all_records = []

    for file_path in file_paths:
        print(f"Loading {file_path}")
        records = load_jl_file(file_path)
        all_records.extend(records)

    return all_records

def load_prechunked_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Prechunked JSON file must contain a list of chunk objects.")

    return data

def _join_entity_list(values):
    if not values:
        return ""

    return ", ".join(
        str(v).strip() for v in values if str(v).strip()
    )


def clean_list(values):
    if not values:
        return []

    return list(set(
        str(v).strip().lower()
        for v in values
        if str(v).strip()
    ))


def derive_risk_hint(exploit_status):
    exploit_status = str(exploit_status).strip().lower()

    if exploit_status == "exploited":
        return "high"
    if exploit_status == "unknown":
        return "medium"
    return "low"


def is_recent(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
        return (datetime.now() - d).days <= 30
    except Exception:
        return False


def extract_text(record):
    data = record["data"]

    title = data.get("title", "")
    summary = data.get("summary", "")
    source = data.get("source", "")
    published_date = data.get("published_date", "")
    url = data.get("url", "")

    products = _join_entity_list(data.get("product", []))
    components = _join_entity_list(data.get("component", []))
    versions = _join_entity_list(data.get("version_strings", []))

    vulnerabilities = _join_entity_list(data.get("Vulnerability", []))
    systems = _join_entity_list(data.get("System", []))
    indicators = _join_entity_list(data.get("Indicator", []))
    malware = _join_entity_list(data.get("Malware", []))
    organizations = _join_entity_list(data.get("Organization", []))

    text = f"""
source: {source}
published_date: {published_date}
title: {title}
summary: {summary}

product: {products}
component: {components}
versions: {versions}

vulnerability_entities: {vulnerabilities}
system_entities: {systems}
indicator_entities: {indicators}
malware_entities: {malware}
organization_entities: {organizations}

url: {url}
""".strip()

    return text


def prepare_chunks(records):
    chunk_records = []

    for record in records:
        data = record["data"]
        text = extract_text(record)

        chunk_records.append({
            "text": text,
            "source_file": record["source_file"],
            "line_number": record["line_number"],
            "url": data.get("url", ""),
            "title": data.get("title", ""),
            "published_date": data.get("published_date", ""),
            "source": data.get("source", ""),
            "catalog_state": data.get("catalog_state", ""),
            "exploit_status": data.get("exploit_status", ""),
            "references": data.get("references", []),
            "indicators_clean": clean_list(data.get("Indicator", [])),
            "systems_clean": clean_list(data.get("System", [])),
            "malware_clean": clean_list(data.get("Malware", [])),
            "organizations_clean": clean_list(data.get("Organization", [])),
            "risk_hint": derive_risk_hint(data.get("exploit_status", "")),
            "is_recent": is_recent(data.get("published_date", "")),
            "num_indicators": len(data.get("Indicator", [])),
            "num_systems": len(data.get("System", [])),
            "num_malware": len(data.get("Malware", [])),
            "num_organizations": len(data.get("Organization", [])),
        })

    return chunk_records
