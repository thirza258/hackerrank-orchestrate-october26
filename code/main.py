"""
Ghost Data Still Exists - Deletion Audit Agent Entry Point.
HackerRank Orchestrate (October 2026).

Usage:
  python3 code/main.py [--dataset-dir dataset] [--output output.csv] [--sample]
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# Add repo root to sys.path to ensure module imports work reliably
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.audit_engine import AuditEngine


def run_audit(dataset_dir: Path, output_file: Path, is_sample: bool = False):
    dataset_dir = Path(dataset_dir)
    output_file = Path(output_file)

    if not dataset_dir.exists():
        print(f"Error: Dataset directory not found: {dataset_dir}", file=sys.stderr)
        sys.exit(1)

    req_file_name = "sample_deletion_requests.csv" if is_sample else "deletion_requests.csv"
    req_path = dataset_dir / req_file_name

    if not req_path.exists():
        print(f"Error: Requests file not found: {req_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Initializing AuditEngine with dataset: {dataset_dir} ...")
    engine = AuditEngine(dataset_dir)

    print(f"Reading requests from: {req_path} ...")
    with open(req_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        case_rows = list(reader)

    print(f"Auditing {len(case_rows)} requests ...")
    results = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for idx, case_row in enumerate(case_rows, 1):
        cid = case_row["case_id"]
        status, steps = engine.audit_case(case_row)
        status_counts[status] = status_counts.get(status, 0) + 1
        steps_str = json.dumps(steps, separators=(",", ":"))
        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_str,
        })
        if idx % 100 == 0 or idx == len(case_rows):
            print(f"Processed {idx}/{len(case_rows)} cases...")

    # Sort results strictly by case_id
    results.sort(key=lambda x: x["case_id"])

    # Write output.csv
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, mode="w", encoding="utf-8", newline="") as f:
        fieldnames = ["case_id", "deletion_status", "steps_json"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"\nAudit complete! Successfully wrote {len(results)} rows to {output_file}")
    print("Summary of decisions:")
    for st, count in sorted(status_counts.items()):
        print(f"  {st}: {count} ({count/len(results)*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Agent")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset"),
        help="Path to dataset directory containing CSVs and evidence/ folder",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output.csv"),
        help="Output CSV path (default: output.csv at repo root)",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Run audit on sample_deletion_requests.csv instead of deletion_requests.csv",
    )

    args = parser.parse_args()
    run_audit(args.dataset_dir, args.output, is_sample=args.sample)


if __name__ == "__main__":
    main()
