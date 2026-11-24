import argparse
import json
import random
import sys
import urllib.error
import urllib.request
from pathlib import Path


def get_json(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def post_json(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    captures = [
        (0, repo / "captures" / "benign"),
        (1, repo / "captures" / "malware"),
    ]

    try:
        health = get_json(args.api + "/health")
        model_info = get_json(args.api + "/model/info")
    except urllib.error.URLError as error:
        print("ERROR: Start the API first:")
        print("  python -m uvicorn ml_analysis.api:app --host 127.0.0.1 --port 8000")
        print("Details:", error)
        return 1

    if not health.get("model_loaded"):
        print("ERROR: model is not loaded.")
        return 1

    rng = random.Random(args.seed)
    selected = []
    for label, directory in captures:
        paths = sorted(directory.glob("*.json"))
        selected.extend((label, path) for path in rng.sample(paths, args.count))
    rng.shuffle(selected)

    feature_names = model_info["feature_names"]
    correct = 0
    print("Native ML replay demo")
    print("Model:", model_info["model_type"])
    print("Training samples:", model_info["training_samples"])
    print("Feature count:", len(feature_names))
    print("")

    for ground_truth, path in selected:
        capture = json.loads(path.read_text(encoding="utf-8"))
        result = post_json(
            args.api + "/predict",
            {
                "session_id": capture.get("session_id", ""),
                "package_name": capture.get("package_name", path.stem),
                "file_operations": [],
                "network_connections": [],
                "process_events": [],
                "dns_queries": [],
                "native_capture": capture,
            },
        )
        expected = "malicious" if ground_truth == 1 else "benign"
        predicted = result["prediction"]
        is_correct = predicted == expected
        correct += int(is_correct)
        print("CORRECT" if is_correct else "MISS")
        print("  Package:", capture.get("package_name", path.stem))
        print("  Ground truth:", expected)
        print("  Model:", predicted)
        print("  Confidence:", f"{float(result['confidence']):.1%}")
        print("")

    total = len(selected)
    print("Summary:", correct, "correct of", total)
    print("Accuracy in this replay selection:", f"{correct / total:.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
