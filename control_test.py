import json
import math
import re
from pathlib import Path
from datetime import datetime

import requests

from config import OLLAMA_URL, OLLAMA_MODEL
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


def build_control_prompt(query: str, description: str):
    prompt = f"""You are a cybersecurity risk analyst.

Assess the following vulnerability description using only the information provided in the description.

You must give a numerical risk score.
If the description is insufficient, say so clearly.

VULNERABILITY DESCRIPTION:
{description}

USER QUERY:
{query}

Return your answer in this format:

Risk Assessment:
- Overall risk level: 0-100
- Confidence: 0-100
- Short justification:

Threats:
- Threat 1:
- Threat 2:
- Threat 3:

Affected Assets / Systems:
- ...

Indicators / Relevant Entities:
- ...

Recommended Next Steps:
- ...

Use concise language and do not invent facts that are not supported by the description.
"""
    return prompt


def ask_ollama_control(query: str, description: str, ollama_url: str, ollama_model: str):
    prompt = build_control_prompt(query, description)

    response = requests.post(
        ollama_url,
        json={
            "model": ollama_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        },
        timeout=120
    )

    response.raise_for_status()
    answer = response.json()["message"]["content"]
    return prompt, answer


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


def run_control_test():
    print("Loading test data...")
    test_items = load_test_data(TEST_DATA_FILE)
    print(f"Loaded {len(test_items)} test cases")

    y_true = []
    y_pred = []

    run_payload = {
        "run_type": "control_test",
        "timestamp": datetime.now().isoformat(),
        "model": OLLAMA_MODEL,
        "test_data_file": str(TEST_DATA_FILE),
        "uses_rag": False,
        "uses_taxonomy": False,
        "cases": []
    }

    for i, item in enumerate(test_items, start=1):
        description = str(item["description"]).strip()
        actual_score = float(item["risk_score"])

        query = "Assess the risk and enumerate the most likely threats from this vulnerability description."

        print(f"\n[{i}/{len(test_items)}] Running control test case...")

        try:
            prompt, answer = ask_ollama_control(
                query=query,
                description=description,
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

    file_path = save_run_file("control_test_run", run_payload)

    print("\nDone.")
    print(f"Saved control test run to: {file_path}")

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
    run_control_test()
