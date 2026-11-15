"""Baseline rules; deliberately does not detect distributed credential stuffing."""
from collections import Counter, defaultdict
from datetime import timedelta
from uuid import uuid4

from app.types import Assessment, Features, SecurityEvent

WINDOW = timedelta(minutes=10)


def features_for(events: list[SecurityEvent]) -> tuple[Features, list[SecurityEvent]]:
    if not events:
        raise ValueError("At least one event is required")
    if len({e.event_id for e in events}) != len(events):
        raise ValueError("Event IDs must be unique")
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    # Select the densest rolling window; ties choose the earliest.
    left = 0
    best = (0, 0)
    for right, event in enumerate(ordered):
        while event.timestamp - ordered[left].timestamp > WINDOW:
            left += 1
        if right + 1 - left > best[1] - best[0]:
            best = (left, right + 1)
    window = ordered[best[0]:best[1]]
    failures = [e for e in window if e.result == "failure"]
    counts = Counter(e.source_ip for e in failures)
    accounts_by_ip = defaultdict(set)
    ips_by_account = defaultdict(set)
    previous = Counter()
    suspicious_success = False
    for e in window:
        if e.result == "failure":
            accounts_by_ip[e.source_ip].add(e.account_id)
            ips_by_account[e.account_id].add(e.source_ip)
            previous[e.account_id] += 1
        elif previous[e.account_id] >= 3:
            suspicious_success = True
    return Features(total_events=len(window), failures=len(failures), max_failures_per_ip=max(counts.values(), default=0), distinct_accounts=len({e.account_id for e in failures}), distinct_ips=len(counts), max_accounts_per_ip=max((len(x) for x in accounts_by_ip.values()), default=0), max_ips_per_account=max((len(x) for x in ips_by_account.values()), default=0), success_after_failures=suspicious_success, window_seconds=int(WINDOW.total_seconds())), window


def assess(scenario_id: str, events: list[SecurityEvent], memory_context: str = "", active_rule=None) -> Assessment:
    features, window = features_for(events)
    retrieval = {}
    if active_rule:
        signature = active_rule.get("signature")
        if signature is None:
            raise ValueError("Active rule has no evidence-backed memory signature")
        dimensions = ("failures", "distinct_ips", "distinct_accounts", "max_failures_per_ip")
        ratios = []
        for name in dimensions:
            a, b = getattr(features, name), getattr(signature, name)
            ratios.append(min(a, b) / max(a, b) if max(a, b) else 1.0)
        similarity = sum(ratios) / len(ratios)
        retrieval = {"memory_id": active_rule["memory_id"], "evidence_id": active_rule["evidence_id"], "similarity": round(similarity, 4), "threshold": 0.6, "applicable": similarity >= 0.6, "method": "mean feature-ratio similarity"}
    if features.success_after_failures:
        classification, action, confidence, rules = "suspicious_login", "escalate", 0.85, ["baseline-success-after-failures-v1"]
        explanation = "A successful login followed at least three failures for the same account in the analysis window."
    elif features.max_failures_per_ip >= 10:
        classification, action, confidence, rules = "single_source_brute_force", "flag", 0.8, ["baseline-single-source-v1"]
        explanation = "One source generated at least ten failed logins in the analysis window."
    elif active_rule and retrieval["applicable"] and (features.failures >= active_rule["rule"].min_failures
                          and features.distinct_ips >= active_rule["rule"].min_ips
                          and features.distinct_accounts >= active_rule["rule"].min_accounts
                          and features.max_failures_per_ip <= active_rule["rule"].max_failures_per_ip):
        classification, action, confidence, rules = "distributed_credential_stuffing", "flag", 0.75, [active_rule["version"]]
        explanation = "An approved distributed-login rule matched the observed features."
    else:
        classification, action, confidence, rules = "benign", "monitor", 0.55, []
        explanation = "No baseline rule matched; this is not proof that the activity is safe."
    return Assessment(decision_id=uuid4().hex, scenario_id=scenario_id, classification=classification, confidence=confidence, action=action, matched_rules=rules, evidence_event_ids=[e.event_id for e in window], features=features, memory_context=memory_context, memory_influences=[active_rule["memory_id"]] if active_rule and active_rule["version"] in rules else [], memory_retrieval=retrieval, explanation=explanation)
