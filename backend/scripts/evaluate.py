#!/usr/bin/env python3
"""
scripts/evaluate.py — Benchmark and evaluation harness for Look-Alike Website Detector.

Reads:
  - data/brands.json (Brand registry)
  - data/phishing_sample.txt (Lookalike/phishing test set)
  - data/legit_sample.txt (Legitimate domains & news articles)

Outputs:
  - Detection rate (Recall / Sensitivity)
  - False-positive rate (FPR)
  - Detailed table of misclassifications for pitch / evaluation metrics
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.rules import analyze_url  # noqa: E402


def load_sample_file(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from a sample file."""
    if not path.exists():
        print(f"[!] File not found: {path}")
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def run_benchmark():
    brands_file = PROJECT_ROOT / "data" / "brands.json"
    phishing_file = PROJECT_ROOT / "data" / "phishing_sample.txt"
    legit_file = PROJECT_ROOT / "data" / "legit_sample.txt"

    if not brands_file.exists():
        print(f"Error: {brands_file} not found. Run from project root.")
        sys.exit(1)

    brands = json.loads(brands_file.read_text(encoding="utf-8"))
    phishing_samples = load_sample_file(phishing_file)
    legit_samples = load_sample_file(legit_file)

    print("=" * 70)
    print("  LOOK-ALIKE WEBSITE DETECTOR — BENCHMARK EVALUATION")
    print("=" * 70)
    print(f"Registry Brands Loaded : {len(brands)}")
    print(f"Phishing Samples       : {len(phishing_samples)}")
    print(f"Legitimate Samples     : {len(legit_samples)}")
    print("-" * 70)

    start_time = time.monotonic()

    # 1. Evaluate Phishing Set
    tp = 0  # Flagged as careful or danger
    fn = 0  # Missed (classified as safe)
    missed_phish = []

    for url in phishing_samples:
        res = analyze_url(url, brands)
        level = res.get("level", "safe")
        score = res.get("score", 0)
        if level in ("danger", "careful"):
            tp += 1
        else:
            fn += 1
            missed_phish.append((url, score, res.get("triggered", [])))

    # 2. Evaluate Legitimate Set
    tn = 0  # Classified as safe
    fp = 0  # False alarm (classified as careful or danger)
    false_positives = []

    for url in legit_samples:
        res = analyze_url(url, brands)
        level = res.get("level", "safe")
        score = res.get("score", 0)
        if level == "safe":
            tn += 1
        else:
            fp += 1
            false_positives.append((url, level, score, res.get("triggered", [])))

    total_time_ms = (time.monotonic() - start_time) * 1000
    total_evals = len(phishing_samples) + len(legit_samples)
    avg_latency_ms = total_time_ms / total_evals if total_evals else 0

    # 3. Metrics
    detection_rate = (tp / len(phishing_samples) * 100) if phishing_samples else 0.0
    fpr = (fp / len(legit_samples) * 100) if legit_samples else 0.0
    accuracy = ((tp + tn) / total_evals * 100) if total_evals else 0.0

    print("\nRESULTS SUMMARY:")
    print(f"  Total URLs Evaluated : {total_evals}")
    print(f"  Total Time           : {total_time_ms:.2f} ms")
    print(f"  Avg Latency per URL  : {avg_latency_ms:.2f} ms")
    print(f"  Detection Rate (TPR) : {detection_rate:.2f}% ({tp}/{len(phishing_samples)})")
    print(f"  False-Positive Rate  : {fpr:.2f}% ({fp}/{len(legit_samples)})")
    print(f"  Overall Accuracy     : {accuracy:.2f}%")
    print("-" * 70)

    # 4. Detailed Misses and False Alarms
    if missed_phish:
        print("\n[!] MISSED PHISHING (False Negatives - classified as SAFE):")
        for url, score, triggered in missed_phish:
            print(f"  - {url} (Score: {score})")
            for t in triggered:
                print(f"      Rule: {t.get('code')} (Weight: {t.get('weight')})")
    else:
        print("\n[✓] No phishing samples missed (100% detection)!")

    if false_positives:
        print("\n[!] FALSE POSITIVES (Legitimate flagged as Careful/Danger):")
        for url, lvl, score, triggered in false_positives:
            print(f"  - {url} -> {lvl.upper()} (Score: {score})")
            for t in triggered:
                print(f"      Rule: {t.get('code')} (Weight: {t.get('weight')})")
    else:
        print("\n[✓] Zero false positives on legitimate test set (0% FPR)!")

    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
