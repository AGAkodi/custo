from datetime import datetime

import pytest
from pydantic import ValidationError

from app.detection import assess, features_for
from app.simulator import generate
from app.types import SecurityEvent


def test_seed_reproducibility_and_expected_baseline():
    assert generate("distributed", 42) == generate("distributed", 42)
    assert generate("distributed", 42) != generate("distributed", 43)
    expected = {"brute-force": "single_source_brute_force", "distributed": "benign", "held-out": "benign", "benign": "benign", "suspicious-success": "suspicious_login"}
    for scenario, label in expected.items():
        result = assess(scenario, generate(scenario, 42))
        assert result.classification == label
        assert result.evidence_event_ids
        assert result.scenario_id == scenario


def test_distinct_features_and_success_order():
    f, _ = features_for(generate("distributed", 42))
    assert f.max_failures_per_ip == 2
    assert f.distinct_accounts == 24
    assert not f.success_after_failures
    f, _ = features_for(generate("suspicious-success", 42))
    assert f.success_after_failures


def test_validation_and_empty_events():
    with pytest.raises(ValueError):
        features_for([])
    event = generate("benign", 42)[0].model_dump()
    event["source_ip"] = "invalid"
    with pytest.raises(ValidationError):
        SecurityEvent(**event)
    event = generate("benign", 42)[0].model_dump()
    event["timestamp"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        SecurityEvent(**event)
    event = generate("benign", 42)[0]
    with pytest.raises(ValueError):
        features_for([event, event])


def test_rolling_window_excludes_old_events():
    from datetime import timedelta
    events = generate("brute-force", 42)
    later = [event.model_copy(update={"event_id": "late-" + event.event_id, "timestamp": event.timestamp + timedelta(hours=2)}) for event in events[:2]]
    features, window = features_for(events + later)
    assert features.total_events == len(events)
    assert all(not event.event_id.startswith("late-") for event in window)
