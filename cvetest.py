import json
import math
import re
from pathlib import Path
from datetime import datetime

from config import (
    RISK_TAX_FILE,
    OLLAMA_URL,
    OLLAMA_MODEL,
    TOP_K,
    CVE_REFERENCE_FILE,
    DATA_FILES,
    EMBED_MODEL_NAME,
)
from ingest import (
    load_risk_taxonomy,
    risk_taxonomy_to_text,
    load_multiple_files,
    prepare_chunks,
    load_prechunked_json,
)
from embed_store import build_vector_store
from retrieve import retrieve_chunks
from generate import ask_ollama
from storage import save_run_file


TEST_DATA_FILE = Path("/home/avint/weakset.json")


def load_test_data(file_path: Path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Test data file must contain a JSON array.")

    validated = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Item {i} is not a JSON object.")
        if "description" not in item or "risk_score" not in item:
            raise ValueError(f"Item {i} must contain 'description' and 'risk_score'.")
        validated.append(item)

    return validated


def extract_risk_score(answer_text: str):
    patterns = [
        r"Overall risk level:\s*(\d+(?:\.\d+)?)",
        r"Overall risk level\s*[-:]\s*(\d+(?:\.\d+)?)",
        r"risk score\s*[-:]\s*(\d+(?:\.\d+)?)",
    ]

    for pattern in patterns:
        match = re.search(pattern, answer_text, re.IGNORECASE)
        if match:
            return float(match.group(1))

    return None


def mean(values):
    return sum(values) / len(values) if values else 0.0


def mse(y_true, y_pred):
    return mean([(a - b) ** 2 for a, b in zip(y_true, y_pred)])


def mae(y_true, y_pred):
    return mean([abs(a - b) for a, b in zip(y_true, y_pred)])


def rmse(y_true, y_pred):
    return math.sqrt(mse(y_true, y_pred))


def pearson_corr(y_true, y_pred):
    if len(y_true) < 2:
        return 0.0

    mean_true = mean(y_true)
    mean_pred = mean(y_pred)

    numerator = sum((a - mean_true) * (b - mean_pred) for a, b in zip(y_true, y_pred))
    denom_true = math.sqrt(sum((a - mean_true) ** 2 for a in y_true))
    denom_pred = math.sqrt(sum((b - mean_pred) ** 2 for b in y_pred))

    if denom_true == 0 or denom_pred == 0:
        return 0.0

    return numerator / (denom_true * denom_pred)


def accuracy_within_threshold(y_true, y_pred, threshold=10):
    correct = sum(1 for a, b in zip(y_true, y_pred) if abs(a - b) <= threshold)
    return correct / len(y_true) if y_true else 0.0


def run_test():
    print("Loading risk taxonomy...")
    taxonomy = load_risk_taxonomy(RISK_TAX_FILE)
    taxonomy_text = risk_taxonomy_to_text(taxonomy)

    print("Loading base records...")
    records = load_multiple_files(DATA_FILES)
    chunk_records = prepare_chunks(records)
    print(f"Prepared {len(chunk_records)} base chunks")

    print("Loading CVE reference chunks...")
    cve_chunks = load_prechunked_json(CVE_REFERENCE_FILE)
    print(f"Loaded {len(cve_chunks)} CVE reference chunks")

    chunk_records.extend(cve_chunks)
    print(f"Total chunks after CVE merge: {len(chunk_records)}")

    print("Building vector store...")
    embed_model, index = build_vector_store(chunk_records, EMBED_MODEL_NAME)
    print("Vector store ready")

    print("Loading test data...")
    test_items = load_test_data(TEST_DATA_FILE)
    print(f"Loaded {len(test_items)} test cases")

    y_true = []
    y_pred = []

    run_payload = {
        "run_type": "test",
        "timestamp": datetime.now().isoformat(),
        "model": OLLAMA_MODEL,
        "test_data_file": str(TEST_DATA_FILE),
        "top_k": TOP_K,
        "num_reference_chunks": len(cve_chunks),
        "config": {
            "DATA_FILES": [str(p) for p in DATA_FILES],
            "CVE_REFERENCE_FILE": str(CVE_REFERENCE_FILE),
            "RISK_TAX_FILE": str(RISK_TAX_FILE),
            "OLLAMA_URL": OLLAMA_URL,
            "OLLAMA_MODEL": OLLAMA_MODEL,
            "EMBED_MODEL_NAME": EMBED_MODEL_NAME,
            "TOP_K": TOP_K,
        },
        "cases": []
    }

    for i, item in enumerate(test_items, start=1):
        description = str(item["description"]).strip()
        actual_score = float(item["risk_score"])

        query = f"""Assess the risk and enumerate the most likely threats from this vulnerability description:

{description}
"""

        print(f"\n[{i}/{len(test_items)}] Running test case...")

        try:
            retrieved_chunks = retrieve_chunks(
                query=query,
                index=index,
                chunk_records=chunk_records,
                embed_model=embed_model,
                top_k=TOP_K
            )

            prompt, answer = ask_ollama(
                query=query,
                retrieved_chunks=retrieved_chunks,
                taxonomy_text=taxonomy_text,
                ollama_url=OLLAMA_URL,
                ollama_model=OLLAMA_MODEL
            )

            predicted_score = extract_risk_score(answer)

            if predicted_score is None:
                raise ValueError(
                    "Could not extract numeric risk score from model output.\n"
                    f"Model output:\n{answer}"
                )

            error = predicted_score - actual_score
            abs_error = abs(error)

            run_payload["cases"].append({
                "case_id": f"case_{i:03d}",
                "description": description,
                "expected_risk_score": actual_score,
                "predicted_risk_score": predicted_score,
                "error": error,
                "absolute_error": abs_error,
                "retrieved_chunks": [
                    {
                        "title": chunk.get("title", ""),
                        "record_type": chunk.get("record_type", ""),
                        "cve_id": chunk.get("cve_id", ""),
                        "risk_score": chunk.get("risk_score", ""),
                        "severity": chunk.get("severity", ""),
                        "text": chunk.get("text", "")
                    }
                    for chunk in retrieved_chunks
                ],
                "prompt": prompt,
                "response": answer
            })

            y_true.append(actual_score)
            y_pred.append(predicted_score)

            print(
                f"Actual: {actual_score} | "
                f"Predicted: {predicted_score:.2f} | "
                f"Absolute Error: {abs_error:.2f}"
            )

        except Exception as e:
            run_payload["cases"].append({
                "case_id": f"case_{i:03d}",
                "description": description,
                "expected_risk_score": actual_score,
                "error_message": str(e)
            })
            print(f"Failed on test case {i}: {e}")

    run_payload["num_test_cases"] = len(test_items)
    run_payload["num_successful_predictions"] = len(y_pred)
    run_payload["num_failed_predictions"] = len(test_items) - len(y_pred)
    run_payload["metrics"] = {
        "mae": mae(y_true, y_pred) if y_true else None,
        "mse": mse(y_true, y_pred) if y_true else None,
        "rmse": rmse(y_true, y_pred) if y_true else None,
        "pearson_correlation": pearson_corr(y_true, y_pred) if y_true else None,
        "accuracy_within_5": accuracy_within_threshold(y_true, y_pred, threshold=5) if y_true else None,
        "accuracy_within_10": accuracy_within_threshold(y_true, y_pred, threshold=10) if y_true else None,
        "accuracy_within_15": accuracy_within_threshold(y_true, y_pred, threshold=15) if y_true else None,
    }

    testset_name = Path(TEST_DATA_FILE).stem
    file_path = save_run_file(f"test_k{TOP_K}_{testset_name}", run_payload)

    print("\nDone.")
    print(f"Saved test run to: {file_path}")

    if y_true:
        print("\nSummary metrics:")
        print(f"MAE: {run_payload['metrics']['mae']:.4f}")
        print(f"MSE: {run_payload['metrics']['mse']:.4f}")
        print(f"RMSE: {run_payload['metrics']['rmse']:.4f}")
        print(f"Pearson Correlation: {run_payload['metrics']['pearson_correlation']:.4f}")
        print(f"Accuracy within 5: {run_payload['metrics']['accuracy_within_5']:.4f}")
        print(f"Accuracy within 10: {run_payload['metrics']['accuracy_within_10']:.4f}")
        print(f"Accuracy within 15: {run_payload['metrics']['accuracy_within_15']:.4f}")


if __name__ == "__main__":
    run_test()
