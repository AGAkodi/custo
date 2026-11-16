import asyncio
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.detection import assess, features_for
from app.lifecycle import derive_candidate, matches
from app.memory import related_incidents
from app.simulator import generate


def spray_events():
    return [e.model_copy(update={"scenario_id": "custom-spray", "source_ip": "192.0.2.10",
                                  "account_id": f"person-{i}"})
            for i, e in enumerate(generate("benign", 42))]


def test_password_spray_candidate_requires_approval_before_detection():
    events = spray_events()
    features, _ = features_for(events)
    rule = derive_candidate(features, "password_spray")
    assert matches(rule, features)
    assert assess("custom-spray", events).classification == "benign"
    active = {"version": "ruleversion:reviewed", "memory_id": "threatmemory:one",
              "evidence_id": "incidentevidence:one", "signature": features, "rule": rule}
    decision = assess("custom-spray", events, active_rule=active)
    assert decision.classification == "password_spray"
    assert decision.memory_influences == ["threatmemory:one"]
    with pytest.raises(ValueError, match="insufficient"):
        derive_candidate(features.model_copy(update={"max_accounts_per_ip": 1}), "password_spray")


def test_related_incidents_require_actual_evidence_provenance(monkeypatch):
    features, _ = features_for(generate("distributed", 42))
    memory = SimpleNamespace(id="threatmemory:one", properties={"feature_signature": features.model_dump_json()})
    evidence = SimpleNamespace(id="incidentevidence:one", type="IncidentEvidence", properties={"decision_id": "abc", "label": "password_spray"})
    source = SimpleNamespace(properties={"assessment_json": json.dumps({"scenario_id": "custom-old"})})

    class Entities:
        async def list(self, **kwargs):
            return SimpleNamespace(items=[memory])
        async def get(self, entity_id):
            return {evidence.id: evidence, "assessment:abc": source}.get(entity_id)

    class Relations:
        async def list(self, **kwargs):
            if kwargs["type"] == "SUPPORTED_BY":
                return SimpleNamespace(items=[SimpleNamespace(to_entity=evidence.id)])
            return SimpleNamespace(items=[object()])

    class Graph:
        entities = Entities()
        relations = Relations()
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("app.memory.memory_graph", lambda settings: Graph())
    result = asyncio.run(related_incidents(None, features))
    assert result[0]["incident_id"] == "custom-old"
    assert result[0]["similarity"] == 1.0
    assert result[0]["evidence_id"] == evidence.id


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires isolated HydraDB")
def test_spray_revision_and_related_incidents_with_real_graph(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main

    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "test-token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "test-token"}
    events = [e.model_dump(mode="json") for e in spray_events()]
    with TestClient(main.app) as client:
        result = client.post("/api/incidents/analyze", json={"incident_id": "custom-spray", "events": events}, headers=headers)
        assert result.status_code == 200, result.text
        decision = result.json()["assessment"]
        feedback = {"decision_id": decision["decision_id"], "confirmed_label": "password_spray",
                    "reviewer": "analyst", "evidence_note": "Verified spray"}
        proposal = client.post("/api/incidents/custom-spray/feedback", json=feedback, headers=headers)
        assert proposal.status_code == 200, proposal.text
        proposal = proposal.json()
        revision = client.post(f"/api/reviews/{proposal['id']}/revise", headers=headers,
                               json={"actor": "analyst", "reason": "Reviewed threshold", "rule": proposal["rule"]})
        assert revision.status_code == 200, revision.text
        revision = revision.json()
        assert revision["revises"] == proposal["id"]
        approved = client.post(f"/api/reviews/{revision['id']}/approve", headers=headers,
                               json={"actor": "analyst", "reason": "Approved"})
        assert approved.status_code == 200, approved.text
        result = client.post("/api/incidents/analyze", json={"incident_id": "custom-spray", "events": events}, headers=headers)
        assert result.status_code == 200, result.text
        assert result.json()["assessment"]["classification"] == "password_spray"
        decision_id = result.json()["assessment"]["decision_id"]
        assert client.get(f"/api/incidents/related/{decision_id}").status_code == 403
        related = client.get(f"/api/incidents/related/{decision_id}", headers=headers)
        assert related.status_code == 200, related.text
        assert related.json()["matches"][0]["evidence_id"] == proposal["evidence_id"]
