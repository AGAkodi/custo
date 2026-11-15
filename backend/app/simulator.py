"""Seeded, fictional authentication scenarios. Labels are never passed to detection."""
from datetime import datetime, timedelta, timezone
from random import Random

from app.types import SecurityEvent

SCENARIOS = {
    "brute-force": ("Single-source brute force", "single_source_brute_force"),
    "distributed": ("Distributed login attempts", "distributed_credential_stuffing"),
    "benign": ("Routine password mistakes", "benign"),
    "benign-shared": ("Shared-network login burst", "benign"),
    "suspicious-success": ("Success after failures", "suspicious_login"),
    "held-out": ("Unseen distributed variation", "distributed_credential_stuffing"),
    "heldout-benign": ("Unseen normal login mistakes", "benign"),
    "heldout-overlap": ("Benign distributed activity", "benign"),
}


def generate(scenario_id: str, seed: int) -> list[SecurityEvent]:
    if scenario_id not in SCENARIOS:
        raise KeyError(scenario_id)
    rng = Random(f"{seed}:{scenario_id}")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    count = {"brute-force": 18, "distributed": 24, "benign": 8, "benign-shared": 60, "suspicious-success": 7, "held-out": 30, "heldout-benign": 9, "heldout-overlap": 24}[scenario_id]
    if scenario_id == "held-out":
        count = 26 + seed % 5
    elif scenario_id == "heldout-overlap":
        count = 24 + seed % 3
    for i in range(count):
        if scenario_id == "brute-force":
            ip, account = "192.0.2.10", f"user-{i % 3:02d}"
        elif scenario_id == "distributed":
            ip, account = f"198.51.100.{10 + i % 12}", f"user-{i:02d}"
        elif scenario_id == "held-out":
            ip, account = f"203.0.113.{80 + (seed % 3) * 12 + i % (9 + seed % 4)}", f"held-{seed}-user-{i:02d}"
        elif scenario_id == "heldout-overlap":
            ip, account = f"203.0.113.{170 + (seed % 3) * 12 + i % 12}", f"overlap-{seed}-user-{i:02d}"
        elif scenario_id == "heldout-benign":
            ip, account = f"192.0.2.{100 + seed % 30 + i % 4}", f"benign-{seed}-user-{i % 4:02d}"
        elif scenario_id == "benign-shared":
            ip, account = f"203.0.113.{30 + i % 12}", f"shared-user-{i % 15:02d}"
        elif scenario_id == "suspicious-success":
            ip, account = "203.0.113.20", "user-01"
        else:
            ip, account = f"203.0.113.{10 + i % 4}", f"user-{i % 4:02d}"
        success = scenario_id == "suspicious-success" and i == count - 1
        events.append(SecurityEvent(event_id=f"{scenario_id}-{i:03d}", timestamp=base + timedelta(seconds=i * (8 if scenario_id == "benign-shared" else 11 + seed % 5 if scenario_id == "held-out" else 13) + rng.randrange(5)), event_type="login_succeeded" if success else "login_failed", source_ip=ip, account_id=account, user_agent="CustosFixture/1.0", result="success" if success else "failure", scenario_id=scenario_id))
    return events

