import json
from pathlib import Path
from datetime import datetime


OUTPUT_ROOT = Path("/home/avint/outputs")


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def ensure_output_root():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)


def save_run_file(prefix: str, payload: dict):
    ensure_output_root()
    file_path = OUTPUT_ROOT / f"{prefix}_{_timestamp()}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return file_path
