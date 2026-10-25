"""
Policy definitions and step ordering rules for Ghost Data Still Exists.
Enforces deletion rules, allowed operations, phases, states, and deterministic step sorting.
"""

from typing import Dict, List, Any


PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

FINDING_OP_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
}

REMEDIATION_OP_ORDER = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
}

VERIFICATION_OP_ORDER = {
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}

OP_TO_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


def sort_key_for_step(step: Dict[str, Any]) -> tuple:
    phase = step["phase"]
    phase_rank = PHASE_ORDER.get(phase, 99)
    op = step["operation"]

    if phase == "FINDING":
        op_rank = FINDING_OP_ORDER.get(op, 99)
    elif phase == "REMEDIATION":
        op_rank = REMEDIATION_OP_ORDER.get(op, 99)
    elif phase == "VERIFICATION":
        op_rank = VERIFICATION_OP_ORDER.get(op, 99)
    else:
        op_rank = 99

    system_id = step.get("system_id", "")
    resource_id = step.get("resource_id", "")
    return (phase_rank, op_rank, system_id, resource_id)


def sort_and_renumber_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts steps according to problem statement contract and numbers them consecutively starting at 1.
    """
    # Remove duplicate steps if any
    unique_steps = []
    seen = set()
    for s in steps:
        key = (s["phase"], s["system_id"], s["resource_id"], s["operation"])
        if key not in seen:
            seen.add(key)
            unique_steps.append(s)

    sorted_steps = sorted(unique_steps, key=sort_key_for_step)
    renumbered = []
    for idx, s in enumerate(sorted_steps, start=1):
        step_dict = {
            "step_no": idx,
            "phase": s["phase"],
            "system_id": s["system_id"],
            "resource_id": s["resource_id"],
            "operation": s["operation"],
            "state": s.get("state") or OP_TO_STATE.get(s["operation"], ""),
            "evidence_id": s.get("evidence_id", ""),
        }
        renumbered.append(step_dict)
    return renumbered
