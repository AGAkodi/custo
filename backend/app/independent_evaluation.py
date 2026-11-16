"""Offline evaluation of an already-frozen rule on analyst-labelled auth incidents.

This does not establish that a dataset is representative or its labels correct.
The split and provenance of the source must be recorded independently.
"""
import argparse
import hashlib
import json
from pathlib import Path

from app.detection import assess
from app.evaluation import metrics
from app.lifecycle import CandidateRule
from app.types import Features, SecurityEvent


def evaluate_documents(training, test, frozen):
    """Assess test incidents without using their labels in detection or rule fitting."""
    if not training or not test:
        raise ValueError("Training and test sets must both contain incidents")
    def validate(cases):
        ids, ips, accounts, parsed = set(), set(), set(), []
        for case in cases:
            incident_id = case["incident_id"]
            if incident_id in ids or case["label"] not in ("benign", "attack"):
                raise ValueError("Incident IDs must be unique and labels must be benign or attack")
            events = [SecurityEvent.model_validate(e) for e in case["events"]]
            if not events or any(e.scenario_id != incident_id for e in events):
                raise ValueError("Every incident must have events with matching scenario IDs")
            ids.add(incident_id)
            ips.update(e.source_ip for e in events)
            accounts.update(e.account_id for e in events)
            parsed.append((case, events))
        return ids, ips, accounts, parsed

    train_ids, train_ips, train_accounts, _ = validate(training)
    test_ids, test_ips, test_accounts, parsed = validate(test)
    if train_ids & test_ids or train_ips & test_ips or train_accounts & test_accounts:
        raise ValueError("Training and test incident IDs, source IPs and account IDs must be disjoint")
    rule = {"version": frozen["version"], "memory_id": frozen["memory_id"],
            "evidence_id": frozen["evidence_id"], "signature": Features.model_validate(frozen["signature"]),
            "rule": CandidateRule.model_validate(frozen["rule"])}
    rows = []
    for case, events in parsed:
        baseline = assess(case["incident_id"], events)
        adaptive = assess(case["incident_id"], events, active_rule=rule)
        rows.append({"incident_id": case["incident_id"], "label": case["label"],
                     "baseline": {"classification": baseline.classification},
                     "adaptive": {"classification": adaptive.classification}})
    return {"sample_size": len(rows), "unit": "incident", "active_version": rule["version"],
            "baseline": metrics(rows, "baseline"), "adaptive": metrics(rows, "adaptive"), "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training", type=Path, required=True, help="JSON array of training incidents")
    parser.add_argument("--test", type=Path, required=True, help="JSON array of held-out incidents")
    parser.add_argument("--frozen-rule", type=Path, required=True, help="Frozen rule and feature signature JSON")
    args = parser.parse_args()
    files = [p.read_bytes() for p in (args.training, args.test, args.frozen_rule)]
    result = evaluate_documents(*(json.loads(data) for data in files))
    result["input_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in zip(("training", "test", "frozen_rule"), files)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
