import asyncio
import json
from types import SimpleNamespace

import pytest

from app.detection import assess, features_for
from app.lifecycle import derive_candidate, history
from app.simulator import generate


def test_heldout_identities_are_disjoint_from_feedback():
    training = generate("distributed", 42)
    for seed in (42, 142, 243, 344, 445):
        for scenario in ("held-out", "heldout-benign", "heldout-overlap"):
            held_out = generate(scenario, seed)
            assert {e.source_ip for e in training}.isdisjoint(e.source_ip for e in held_out)
            assert {e.account_id for e in training}.isdisjoint(e.account_id for e in held_out)


def test_candidate_is_derived_from_evidence_and_rejects_insufficient_data():
    features, _ = features_for(generate("distributed", 42))
    candidate = derive_candidate(features)
    assert candidate.min_accounts == 12
    varied = features.model_copy(update={"failures": 40, "distinct_accounts": 40, "distinct_ips": 16})
    new_candidate = derive_candidate(varied)
    assert new_candidate.min_accounts == 20
    assert new_candidate.min_ips == 8
    with pytest.raises(ValueError):
        derive_candidate(features.model_copy(update={"distinct_ips": 1}))


def test_graph_memory_relevance_gates_rule():
    features, _ = features_for(generate("distributed", 42))
    candidate = derive_candidate(features)
    rule = {"rule": candidate, "version": "ruleversion:test", "memory_id": "threatmemory:test", "evidence_id": "incidentevidence:test", "signature": features}
    matching = assess("held-out", generate("held-out", 42), active_rule=rule)
    assert matching.classification == "distributed_credential_stuffing"
    assert matching.memory_retrieval["applicable"]
    # Even if the thresholds match, an unrelated memory signature cannot influence the decision.
    unrelated = features.model_copy(update={"failures": 1000, "distinct_ips": 1000, "distinct_accounts": 1000, "max_failures_per_ip": 1000})
    suppressed = assess("held-out", generate("held-out", 42), active_rule={**rule, "signature": unrelated})
    assert suppressed.classification == "benign"
    assert not suppressed.memory_retrieval["applicable"]
    assert suppressed.memory_influences == []


def test_uncommitted_lifecycle_event_cannot_activate_rule():
    class Entities:
        async def list(self, **kwargs):
            records = [SimpleNamespace(id="lifecycleevent:orphan", properties={"data": json.dumps({"id":"orphan", "proposal_id":"one", "kind":"APPROVED", "timestamp":"2026-01-01", "active_version":"ruleversion:one"})}), SimpleNamespace(id="lifecycleevent:committed", properties={"data": json.dumps({"id":"committed", "proposal_id":"two", "kind":"PROPOSED", "timestamp":"2026-01-02"})})]
            return SimpleNamespace(items=records, next_cursor=None)
    class Relations:
        async def list(self, **kwargs):
            return SimpleNamespace(items=[object()] if kwargs["from_entity"].endswith("committed") else [])
    graph = SimpleNamespace(entities=Entities(), relations=Relations())
    records = asyncio.run(history(graph))
    assert [record["id"] for record in records] == ["committed"]
