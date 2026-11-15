"""Incident-level, deterministic comparison on fixtures excluded from feedback."""
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.detection import assess
from app.lifecycle import current_rule
from app.memory import memory_graph, record_assessment
from app.simulator import SCENARIOS, generate

CASES = ("held-out", "heldout-benign", "heldout-overlap")
SEED_OFFSETS = (100, 201, 302, 403)


def metrics(rows, key):
    tp = fp = tn = fn = 0
    for row in rows:
        actual = row["label"] != "benign"
        predicted = row[key]["classification"] != "benign"
        tp += actual and predicted
        fp += not actual and predicted
        tn += not actual and not predicted
        fn += actual and not predicted
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0, "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0}


async def evaluate(settings):
    rule = await current_rule(settings)
    rows = []
    for scenario in CASES:
        for offset in SEED_OFFSETS:
            case_seed = settings.demo_seed + offset
            events = generate(scenario, case_seed)
            baseline = assess(scenario, events)
            adaptive = assess(scenario, events, active_rule=rule)
            await record_assessment(settings, baseline)
            await record_assessment(settings, adaptive)
            # Full decisions are stored separately; keep the run below HydraDB's document limit.
            fields = {"decision_id", "classification", "matched_rules", "memory_influences", "memory_retrieval"}
            rows.append({"scenario_id": scenario, "seed": case_seed, "label": SCENARIOS[scenario][1], "baseline": baseline.model_dump(mode="json", include=fields), "adaptive": adaptive.model_dump(mode="json", include=fields)})
    result = {"id": uuid4().hex, "created_at": datetime.now(timezone.utc).isoformat(), "seed": settings.demo_seed, "unit": "incident", "positive_class": "non-benign incident", "sample_size": len(rows), "active_version": rule["version"] if rule else None, "baseline": metrics(rows, "baseline"), "adaptive": metrics(rows, "adaptive"), "cases": rows}
    async with memory_graph(settings) as graph:
        await graph.entities.create("Evaluation " + result["id"], "EvaluationRun", id="evaluationrun:" + result["id"], properties={"data": json.dumps(result)})
    return result
