import pytest

from app.detection import features_for
from app.independent_evaluation import evaluate_documents
from app.lifecycle import derive_candidate
from app.simulator import generate
from app.types import Features


def case(scenario, label):
    events = generate(scenario, 42)
    return {"incident_id": scenario, "label": label,
            "events": [event.model_dump(mode="json") for event in events]}


def frozen():
    signature, _ = features_for(generate("distributed", 42))
    return {"version": "ruleversion:test", "memory_id": "threatmemory:test",
            "evidence_id": "incidentevidence:test", "signature": signature.model_dump(),
            "rule": derive_candidate(signature).model_dump()}


def test_frozen_rule_is_evaluated_against_disjoint_incidents():
    result = evaluate_documents([case("distributed", "attack")],
                                [case("held-out", "attack"), case("heldout-overlap", "benign")], frozen())
    assert result["baseline"]["fn"] == 1
    assert result["adaptive"]["tp"] == 1
    assert result["adaptive"]["fp"] == 1


def test_rejects_overlapping_identities_and_invalid_labels():
    training = case("distributed", "attack")
    heldout = case("held-out", "attack")
    heldout["events"][0]["source_ip"] = training["events"][0]["source_ip"]
    with pytest.raises(ValueError, match="disjoint"):
        evaluate_documents([training], [heldout], frozen())
    heldout["label"] = "unknown"
    with pytest.raises(ValueError, match="labels"):
        evaluate_documents([training], [heldout], frozen())


def test_memory_comparison_explains_feature_scores():
    from app.detection import assess
    data = frozen()
    data["signature"] = Features.model_validate(data["signature"])
    data["rule"] = derive_candidate(data["signature"])
    result = assess("held-out", generate("held-out", 42), active_rule=data)
    comparison = result.memory_retrieval["comparisons"]["failures"]
    assert comparison["observed"] == result.features.failures
    assert comparison["reference"] == 24
