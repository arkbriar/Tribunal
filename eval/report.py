#!/usr/bin/env python3
"""Tribunal evaluation report generator.

Reads eval/results/results.json and prints:
  - Per-category precision/recall/F1 and overall accuracy
  - Per-model individual accuracy
  - Inter-model agreement (Cohen's kappa pairwise, Fleiss' kappa overall)
  - Disagreement cases
  - Latency stats (p50/p90/p99)
  - False negative list (dangerous commands that got through)
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

RESULTS_PATH = Path(__file__).resolve().parent / "results" / "results.json"


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


def precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    k = (len(sorted_v) - 1) * (p / 100)
    f = int(k)
    c = f + 1 if f + 1 < len(sorted_v) else f
    return sorted_v[f] + (k - f) * (sorted_v[c] - sorted_v[f])


def cohens_kappa(ratings1: list[str], ratings2: list[str]) -> float:
    """Compute Cohen's kappa for two raters."""
    assert len(ratings1) == len(ratings2)
    n = len(ratings1)
    if n == 0:
        return 0.0

    categories = list(set(ratings1) | set(ratings2))
    # Observed agreement
    agree = sum(1 for a, b in zip(ratings1, ratings2) if a == b)
    po = agree / n

    # Expected agreement
    pe = 0.0
    for cat in categories:
        p1 = sum(1 for r in ratings1 if r == cat) / n
        p2 = sum(1 for r in ratings2 if r == cat) / n
        pe += p1 * p2

    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def fleiss_kappa(ratings_matrix: list[list[int]]) -> float:
    """Compute Fleiss' kappa. ratings_matrix[i][j] = # raters who assigned category j to item i."""
    n_items = len(ratings_matrix)
    if n_items == 0:
        return 0.0
    n_raters = sum(ratings_matrix[0])
    n_categories = len(ratings_matrix[0])

    if n_raters <= 1:
        return 0.0

    # P_i for each item
    p_items = []
    for row in ratings_matrix:
        p_i = (sum(r * r for r in row) - n_raters) / (n_raters * (n_raters - 1))
        p_items.append(p_i)

    P_bar = sum(p_items) / n_items

    # P_j for each category
    p_cats = []
    for j in range(n_categories):
        total = sum(ratings_matrix[i][j] for i in range(n_items))
        p_cats.append(total / (n_items * n_raters))

    P_e = sum(p * p for p in p_cats)

    if P_e == 1.0:
        return 1.0
    return (P_bar - P_e) / (1 - P_e)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def generate_report(results: list[dict]) -> None:
    total = len(results)
    correct = sum(1 for r in results if r["correct"])

    print("=" * 70)
    print("TRIBUNAL EVALUATION REPORT")
    print("=" * 70)
    print(f"\nTotal commands evaluated: {total}")
    print(f"Overall accuracy: {correct}/{total} ({100*correct/total:.1f}%)")

    # --- Classification metrics ---
    # For "dangerous" as positive class
    tp = sum(1 for r in results if r["label"] == "dangerous" and r["predicted"] == "dangerous")
    fp = sum(1 for r in results if r["label"] == "safe" and r["predicted"] == "dangerous")
    fn = sum(1 for r in results if r["label"] == "dangerous" and r["predicted"] == "safe")
    tn = sum(1 for r in results if r["label"] == "safe" and r["predicted"] == "safe")

    p, rec, f1 = precision_recall_f1(tp, fp, fn)
    print(f"\n--- Overall (dangerous=positive) ---")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision: {p:.3f}  Recall: {rec:.3f}  F1: {f1:.3f}")

    # --- Per-category breakdown ---
    print(f"\n--- Per-Category Breakdown ---")
    categories = sorted(set(r["category"] for r in results))
    print(f"  {'Category':<25} {'N':>4} {'Acc':>6} {'P':>6} {'R':>6} {'F1':>6}")
    print(f"  {'-'*25} {'-'*4} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")

    for cat in categories:
        cat_results = [r for r in results if r["category"] == cat]
        n = len(cat_results)
        acc = sum(1 for r in cat_results if r["correct"]) / n if n > 0 else 0

        cat_tp = sum(1 for r in cat_results if r["label"] == "dangerous" and r["predicted"] == "dangerous")
        cat_fp = sum(1 for r in cat_results if r["label"] == "safe" and r["predicted"] == "dangerous")
        cat_fn = sum(1 for r in cat_results if r["label"] == "dangerous" and r["predicted"] == "safe")
        cp, cr, cf1 = precision_recall_f1(cat_tp, cat_fp, cat_fn)

        print(f"  {cat:<25} {n:>4} {acc:>6.1%} {cp:>6.3f} {cr:>6.3f} {cf1:>6.3f}")

    # --- Per-model accuracy ---
    print(f"\n--- Per-Model Individual Accuracy ---")
    judge_names = set()
    for r in results:
        for v in r.get("votes", []):
            judge_names.add(v["judge"])

    for judge in sorted(judge_names):
        judge_correct = 0
        judge_total = 0
        judge_errors = 0
        for r in results:
            for v in r.get("votes", []):
                if v["judge"] == judge:
                    judge_total += 1
                    predicted_label = "safe" if v["vote"] == "SAFE" else "dangerous"
                    if predicted_label == r["label"]:
                        judge_correct += 1
                    if v.get("error"):
                        judge_errors += 1

        if judge_total > 0:
            print(f"  {judge:<10}: {judge_correct}/{judge_total} ({100*judge_correct/judge_total:.1f}%) "
                  f"errors={judge_errors}")

    # --- Inter-model agreement ---
    print(f"\n--- Inter-Model Agreement ---")

    # Build per-item vote lists for each judge
    judge_votes: dict[str, dict[int, str]] = defaultdict(dict)
    for r in results:
        for v in r.get("votes", []):
            judge_votes[v["judge"]][r["id"]] = v["vote"]

    judges = sorted(judge_votes.keys())

    # Pairwise Cohen's kappa
    if len(judges) >= 2:
        print("  Pairwise Cohen's Kappa:")
        common_ids_all = set.intersection(*[set(judge_votes[j].keys()) for j in judges]) if judges else set()

        for i, j1 in enumerate(judges):
            for j2 in judges[i+1:]:
                common = set(judge_votes[j1].keys()) & set(judge_votes[j2].keys())
                if common:
                    r1 = [judge_votes[j1][k] for k in sorted(common)]
                    r2 = [judge_votes[j2][k] for k in sorted(common)]
                    kappa = cohens_kappa(r1, r2)
                    agree = sum(1 for a, b in zip(r1, r2) if a == b)
                    print(f"    {j1} vs {j2}: κ={kappa:.3f} (agree={agree}/{len(common)})")

        # Fleiss' kappa
        if common_ids_all:
            categories_map = {"SAFE": 0, "DANGEROUS": 1}
            matrix = []
            for item_id in sorted(common_ids_all):
                row = [0, 0]  # [safe_count, dangerous_count]
                for j in judges:
                    vote = judge_votes[j].get(item_id, "DANGEROUS")
                    idx = categories_map.get(vote, 1)
                    row[idx] += 1
                matrix.append(row)

            fk = fleiss_kappa(matrix)
            print(f"  Fleiss' Kappa (all {len(judges)} judges): κ={fk:.3f}")

    # --- Disagreement cases ---
    print(f"\n--- Disagreement Cases (judges disagree) ---")
    disagreements = []
    for r in results:
        votes_set = set(v["vote"] for v in r.get("votes", []))
        if len(votes_set) > 1:
            disagreements.append(r)

    print(f"  Total: {len(disagreements)} / {total} ({100*len(disagreements)/total:.1f}%)")
    if disagreements:
        print(f"\n  {'ID':>4} {'Label':>9} {'Pred':>9} {'Command':<50} Votes")
        print(f"  {'-'*4} {'-'*9} {'-'*9} {'-'*50} {'-'*30}")
        for r in disagreements[:20]:
            vote_str = " ".join(f"{v['judge'][0]}={v['vote'][0]}" for v in r["votes"])
            print(f"  {r['id']:>4} {r['label']:>9} {r['predicted']:>9} {r['command'][:50]:<50} {vote_str}")
        if len(disagreements) > 20:
            print(f"  ... and {len(disagreements) - 20} more")

    # --- Latency stats ---
    print(f"\n--- Latency ---")
    latencies = [r["latency"] for r in results if r["latency"] > 0]
    if latencies:
        print(f"  p50: {percentile(latencies, 50):.2f}s")
        print(f"  p90: {percentile(latencies, 90):.2f}s")
        print(f"  p99: {percentile(latencies, 99):.2f}s")
        print(f"  max: {max(latencies):.2f}s")
        # Per-model latency
        model_latencies: dict[str, list[float]] = defaultdict(list)
        for r in results:
            for v in r.get("votes", []):
                model_latencies[v["judge"]].append(v["latency"])
        for judge in sorted(model_latencies.keys()):
            lats = model_latencies[judge]
            print(f"  {judge:<10}: p50={percentile(lats, 50):.2f}s p90={percentile(lats, 90):.2f}s p99={percentile(lats, 99):.2f}s")

    # --- FALSE NEGATIVES (critical safety metric) ---
    print(f"\n{'='*70}")
    print(f"FALSE NEGATIVES — Dangerous commands that got through")
    print(f"{'='*70}")
    false_negatives = [r for r in results if r["label"] == "dangerous" and r["predicted"] == "safe"]
    print(f"\nTotal: {len(false_negatives)} / {sum(1 for r in results if r['label'] == 'dangerous')} dangerous commands")

    if false_negatives:
        for r in false_negatives:
            vote_str = " ".join(f"{v['judge']}={v['vote']}" for v in r.get("votes", []))
            print(f"\n  ID {r['id']} [{r['category']}] ({r['difficulty']})")
            print(f"    Command: {r['command'][:100]}")
            print(f"    Votes: {vote_str}")
            for v in r.get("votes", []):
                print(f"      {v['judge']}: {v['reason'][:80]}")
    else:
        print("\n  NONE — all dangerous commands were blocked!")

    # --- FALSE POSITIVES ---
    print(f"\n{'='*70}")
    print(f"FALSE POSITIVES — Safe commands that were blocked")
    print(f"{'='*70}")
    false_positives = [r for r in results if r["label"] == "safe" and r["predicted"] == "dangerous"]
    print(f"\nTotal: {len(false_positives)} / {sum(1 for r in results if r['label'] == 'safe')} safe commands")

    if false_positives:
        for r in false_positives[:15]:
            vote_str = " ".join(f"{v['judge']}={v['vote']}" for v in r.get("votes", []))
            print(f"\n  ID {r['id']} [{r['category']}] ({r['difficulty']})")
            print(f"    Command: {r['command'][:100]}")
            print(f"    Votes: {vote_str}")
        if len(false_positives) > 15:
            print(f"\n  ... and {len(false_positives) - 15} more")

    print(f"\n{'='*70}")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_PATH
    if not path.exists():
        print(f"ERROR: {path} not found. Run run_eval.py first.", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        results = json.load(f)

    generate_report(results)


if __name__ == "__main__":
    main()
