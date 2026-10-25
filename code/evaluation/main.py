"""
Evaluation runner for Ghost Data Still Exists.
Computes case-level status accuracy, step-level accuracy, field-level accuracy,
sequence accuracy, and custom evaluation cases.

Usage:
  python3 code/evaluation/main.py
"""

import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.audit_engine import AuditEngine


def evaluate_predictions(expected_file: Path, predicted_steps_map: Dict[str, Tuple[str, List[Dict[str, Any]]]]):
    with open(expected_file, mode="r", encoding="utf-8") as f:
        expected_rows = list(csv.DictReader(f))

    total_cases = len(expected_rows)
    status_matches = 0
    perfect_cases = 0

    total_exp_steps = 0
    total_pred_steps = 0
    exact_step_matches = 0

    field_matches = {
        "step_no": 0,
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    total_field_comparisons = 0

    sequence_matches = 0

    for row in expected_rows:
        cid = row["case_id"]
        exp_status = row["deletion_status"]
        exp_steps = json.loads(row["steps_json"])

        pred_status, pred_steps = predicted_steps_map[cid]

        if pred_status == exp_status:
            status_matches += 1

        total_exp_steps += len(exp_steps)
        total_pred_steps += len(pred_steps)

        # Sequence match check: exact match of (phase, operation, system_id, resource_id) across all steps
        if len(pred_steps) == len(exp_steps):
            is_seq_match = True
            for ps, es in zip(pred_steps, exp_steps):
                if (ps.get("phase"), ps.get("operation"), ps.get("system_id"), ps.get("resource_id")) != \
                   (es.get("phase"), es.get("operation"), es.get("system_id"), es.get("resource_id")):
                    is_seq_match = False
                    break
            if is_seq_match:
                sequence_matches += 1

        # Step and field comparisons
        matched_in_case = 0
        min_len = min(len(pred_steps), len(exp_steps))
        for i in range(min_len):
            ps = pred_steps[i]
            es = exp_steps[i]
            total_field_comparisons += 1
            if ps == es:
                matched_in_case += 1

            for k in field_matches:
                if ps.get(k) == es.get(k):
                    field_matches[k] += 1

        exact_step_matches += matched_in_case
        if pred_status == exp_status and pred_steps == exp_steps:
            perfect_cases += 1

    metrics = {
        "total_cases": total_cases,
        "status_accuracy": status_matches / total_cases if total_cases else 0.0,
        "perfect_case_accuracy": perfect_cases / total_cases if total_cases else 0.0,
        "exact_step_accuracy": exact_step_matches / total_exp_steps if total_exp_steps else 0.0,
        "sequence_accuracy": sequence_matches / total_cases if total_cases else 0.0,
        "field_accuracies": {
            k: field_matches[k] / total_field_comparisons if total_field_comparisons else 0.0
            for k in field_matches
        },
        "total_exp_steps": total_exp_steps,
        "total_pred_steps": total_pred_steps,
        "status_matches": status_matches,
        "perfect_cases": perfect_cases,
        "exact_step_matches": exact_step_matches,
        "sequence_matches": sequence_matches,
    }
    return metrics


def run_custom_cases_evaluation(engine: AuditEngine):
    """
    Evaluates at least three additional participant-created evaluation cases
    to verify edge cases:
    1. custom_case_01: Non-deletion data portability inquiry under GDPR Article 20.
    2. custom_case_02: Deletion complete with account tombstone redaction and security audit log retention.
    3. custom_case_03: Active data sync recreating customer search index after primary profile deletion.
    """
    custom_cases = [
        {
            "case_id": "custom_case_01",
            "email": "sarah.connor@example.com",
            "requested_at": "2026-09-10T10:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-11T10:00:00Z",
            "audit_at": "2026-09-15T10:00:00Z",
            "request_text": "Please send me a copy of all personal data and order history that you hold. Do not close my account or delete my data.",
            "expected_status": "NOT_APPLICABLE",
            "expected_steps_len": 0,
        },
        {
            "case_id": "custom_case_02",
            "email": "a.eze08@gmail.com",
            "requested_at": "2026-09-04T12:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-06T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
            "request_text": "I no longer need this account. Please remove my name and contact details, but keeping an internal deleted-account reference is fine.",
            "expected_status": "COMPLETE",
            "expected_steps_len": 3,
        },
        {
            "case_id": "custom_case_03",
            "email": "keiko.nakamura@gmail.com",
            "requested_at": "2026-09-01T12:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-02T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
            "request_text": "Please delete all personal data associated with my account.",
            "expected_status": "INCOMPLETE",
            "expected_steps_len": 6,
        },
    ]

    results = []
    for c in custom_cases:
        status, steps = engine.audit_case(c)
        passed = (status == c["expected_status"])
        results.append({
            "case_id": c["case_id"],
            "expected_status": c["expected_status"],
            "predicted_status": status,
            "passed": passed,
            "step_count": len(steps),
        })
    return results


def main():
    dataset_dir = Path("dataset")
    engine = AuditEngine(dataset_dir)

    with open(dataset_dir / "sample_deletion_requests.csv", encoding="utf-8") as f:
        sample_cases = list(csv.DictReader(f))

    predictions = {}
    for case in sample_cases:
        st, steps = engine.audit_case(case)
        predictions[case["case_id"]] = (st, steps)

    metrics = evaluate_predictions(dataset_dir / "sample_output.csv", predictions)
    custom_results = run_custom_cases_evaluation(engine)

    print("==========================================================")
    print("        Ghost Data Still Exists - Evaluation Report       ")
    print("==========================================================")
    print(f"Case-Level Deletion Status Accuracy: {metrics['status_matches']}/{metrics['total_cases']} ({metrics['status_accuracy']*100:.2f}%)")
    print(f"Perfect Case Accuracy (Status + All Steps): {metrics['perfect_cases']}/{metrics['total_cases']} ({metrics['perfect_case_accuracy']*100:.2f}%)")
    print(f"Exact Step Match Accuracy: {metrics['exact_step_matches']}/{metrics['total_exp_steps']} ({metrics['exact_step_accuracy']*100:.2f}%)")
    print(f"Sequence Accuracy: {metrics['sequence_matches']}/{metrics['total_cases']} ({metrics['sequence_accuracy']*100:.2f}%)")
    print("\nField-Level Accuracies:")
    for field, acc in metrics["field_accuracies"].items():
        print(f"  - {field}: {acc*100:.2f}%")

    print("\nCustom Edge-Case Evaluation:")
    for cr in custom_results:
        mark = "PASS" if cr["passed"] else "FAIL"
        print(f"  - [{mark}] {cr['case_id']}: Exp={cr['expected_status']}, Pred={cr['predicted_status']} ({cr['step_count']} steps)")
    print("==========================================================")


if __name__ == "__main__":
    main()
