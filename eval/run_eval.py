#!/usr/bin/env python3
"""Tribunal evaluation runner.

Calls vote_review logic directly (in-process, no subprocess), sharing a single
async HTTP client for all commands. Much faster than spawning subprocesses.

Features:
  - Async concurrent execution (configurable workers via semaphore)
  - Shared httpx.AsyncClient with connection pooling
  - Retry on API errors with exponential backoff
  - Resume from partial results

Usage:
  python eval/run_eval.py                    # full dataset
  python eval/run_eval.py 20                 # first 20
  python eval/run_eval.py source=gtfobins    # filter
  python eval/run_eval.py --workers=8        # concurrency
  python eval/run_eval.py --resume           # resume from previous results
  python eval/run_eval.py --retries=3        # retry failed entries

Output: eval/results/results.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

# Add project root to path so we can import vote_review
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import vote_review  # noqa: E402

DATASET = ROOT / "eval" / "dataset.json"
RESULTS_DIR = ROOT / "eval" / "results"


def has_api_errors(result: dict) -> bool:
    """Check if a result has API errors (for retry logic)."""
    votes = result.get("votes", [])
    if not votes:
        return True  # no votes means something went wrong
    return any(v.get("error") for v in votes)


async def run_one(
    client: "httpx.AsyncClient",
    entry: dict,
    retries: int,
    sem: asyncio.Semaphore,
) -> dict:
    """Run the hook logic on a single command in-process."""
    command = entry["command"]

    async with sem:
        # Layer 1: trivially safe
        if vote_review.is_trivially_safe(command):
            return {
                "id": entry["id"],
                "command": command,
                "label": entry["label"],
                "predicted": "safe",
                "correct": entry["label"] == "safe",
                "exit_code": 0,
                "votes": [],
                "latency": 0.0,
                "category": entry.get("category", ""),
                "source": entry.get("source", ""),
                "difficulty": entry.get("difficulty", ""),
                "layer": "allowlist",
            }

        # Layer 2: blocklist
        block_reason = vote_review.check_blocklist(command)
        if block_reason:
            return {
                "id": entry["id"],
                "command": command,
                "label": entry["label"],
                "predicted": "dangerous",
                "correct": entry["label"] == "dangerous",
                "exit_code": 2,
                "votes": [],
                "latency": 0.0,
                "category": entry.get("category", ""),
                "source": entry.get("source", ""),
                "difficulty": entry.get("difficulty", ""),
                "layer": "blocklist",
                "block_reason": block_reason,
            }

        # Layer 3: LLM judges
        last_votes = []
        for attempt in range(1 + retries):
            if attempt > 0:
                await asyncio.sleep(min(2 ** attempt, 10))

            t0 = time.monotonic()
            try:
                votes = await asyncio.wait_for(
                    asyncio.gather(
                        *(vote_review.judge_command(client, m, command)
                          for m in vote_review.MODELS)
                    ),
                    timeout=vote_review.TIMEOUT + 5,
                )
                votes = list(votes)
            except asyncio.TimeoutError:
                votes = [{
                    "judge": m["name"], "model": m["model"],
                    "vote": "DANGEROUS", "reason": "timeout",
                    "latency": time.monotonic() - t0, "error": "timeout",
                } for m in vote_review.MODELS]

            elapsed = time.monotonic() - t0
            last_votes = votes

            if not any(v.get("error") for v in votes):
                break

        allowed = vote_review.tally_votes(last_votes)
        predicted = "safe" if allowed else "dangerous"

        return {
            "id": entry["id"],
            "command": command,
            "label": entry["label"],
            "predicted": predicted,
            "correct": predicted == entry["label"],
            "exit_code": 0 if allowed else 2,
            "votes": last_votes,
            "latency": elapsed,
            "category": entry.get("category", ""),
            "source": entry.get("source", ""),
            "difficulty": entry.get("difficulty", ""),
            "layer": "judges",
        }


async def async_main() -> None:
    parser = argparse.ArgumentParser(description="Tribunal evaluation runner")
    parser.add_argument("filter", nargs="?", help="Subset size (int) or filter (key=value)")
    parser.add_argument("--workers", "-w", type=int, default=5, help="Concurrent workers (default: 5)")
    parser.add_argument("--retries", "-r", type=int, default=2, help="Retries per command on API error (default: 2)")
    parser.add_argument("--resume", action="store_true", help="Resume from previous results, skip completed IDs")
    args = parser.parse_args()

    if not DATASET.exists():
        print(f"ERROR: {DATASET} not found. Run build_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    with open(DATASET) as f:
        dataset = json.load(f)

    # Apply filter
    if args.filter:
        try:
            n = int(args.filter)
            dataset = dataset[:n]
        except ValueError:
            key, val = args.filter.split("=", 1)
            dataset = [d for d in dataset if d.get(key) == val]

    # Resume: load previous results and skip completed IDs without errors
    completed: dict[int, dict] = {}
    output_path = RESULTS_DIR / "results.json"
    if args.resume and output_path.exists():
        with open(output_path) as f:
            prev_results = json.load(f)
        for r in prev_results:
            if not has_api_errors(r):
                completed[r["id"]] = r
        print(f"Resuming: {len(completed)} clean results loaded, skipping those IDs")

    todo = [d for d in dataset if d["id"] not in completed]
    total = len(dataset)

    print(f"Running evaluation: {len(todo)} to process ({total} total, {len(completed)} cached)", flush=True)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    sem = asyncio.Semaphore(args.workers)
    done_count = len(completed)

    async with vote_review.httpx.AsyncClient(timeout=vote_review.TIMEOUT) as client:

        async def process(entry: dict) -> dict:
            nonlocal done_count
            result = await run_one(client, entry, args.retries, sem)
            done_count += 1

            status = "OK" if result["correct"] else "MISS"
            vote_summary = ""
            if result["votes"]:
                vote_summary = " | " + " ".join(
                    f"{v['judge']}={v['vote'][0]}" for v in result["votes"]
                )
            err_flag = " [ERR]" if has_api_errors(result) else ""
            layer = f" ({result.get('layer', '')})" if result.get("layer") != "judges" else ""

            print(
                f"  [{done_count:3d}/{total}] {status} {result['predicted']:>9} "
                f"(actual={result['label']:>9}) {result['latency']:5.1f}s"
                f"{vote_summary}{err_flag}{layer}  {entry['command'][:55]}",
                flush=True,
            )
            return result

        tasks = [process(e) for e in todo]
        new_results_list = await asyncio.gather(*tasks)

    new_results = {r["id"]: r for r in new_results_list}

    # Merge completed + new results, ordered by dataset ID
    all_results = {**completed, **new_results}
    ordered = [all_results[d["id"]] for d in dataset if d["id"] in all_results]

    with open(output_path, "w") as f:
        json.dump(ordered, f, indent=2)

    correct = sum(1 for r in ordered if r["correct"])
    errors = sum(1 for r in ordered if has_api_errors(r))
    print(f"\nAccuracy: {correct}/{len(ordered)} ({100*correct/len(ordered):.1f}%)")
    print(f"API errors: {errors}/{len(ordered)}")
    print(f"Results saved to {output_path}")


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
