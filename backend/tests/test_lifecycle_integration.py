import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_feedback_approval_held_out_and_rollback(monkeypatch):
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "test-review-token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "test-review-token"}
    reviewer = {"actor": "test analyst", "reason": "fixture evidence reviewed"}
    with TestClient(main.app) as client:
        baseline = client.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
        assert baseline["classification"] == "benign"
        held_out = client.post("/api/scenarios/held-out/run?baseline=true").json()["assessment"]
        assert held_out["classification"] == "benign"
        body = {"decision_id": baseline["decision_id"]}
        assert client.post("/api/scenarios/distributed/feedback", json=body).status_code == 403
        assert client.post("/api/scenarios/held-out/feedback", json={"decision_id": held_out["decision_id"]}, headers=headers).status_code == 409
        result = client.post("/api/scenarios/distributed/feedback", json=body, headers=headers)
        assert result.status_code == 200, result.text
        proposal = result.json()
        assert proposal["regression"]["feedback_matches"]
        assert not proposal["regression"]["benign_matches"]
        assert proposal["regression"]["benign_results"] == {"benign": False, "benign-shared": False}
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "benign"
        approved = client.post(f"/api/reviews/{proposal['id']}/approve", json=reviewer, headers=headers)
        assert approved.status_code == 200, approved.text
        changed = client.post("/api/scenarios/held-out/run").json()["assessment"]
        assert changed["classification"] == "distributed_credential_stuffing"
        assert proposal["memory_id"] in changed["memory_influences"]
        evaluated = client.post("/api/evaluation/run")
        assert evaluated.status_code == 200, evaluated.text
        metrics = evaluated.json()
        assert client.get("/api/evaluation/latest").json()["id"] == metrics["id"]
        assert metrics["sample_size"] == 12
        assert metrics["baseline"]["fn"] == 4
        assert metrics["adaptive"]["tp"] == 4
        assert metrics["adaptive"]["fp"] == 4
        assert metrics["adaptive"]["false_positive_rate"] == 0.5
        graph = client.get("/api/graph/neighborhood")
        assert graph.status_code == 200, graph.text
        graph_data = graph.json()
        assert any(e["source"] == proposal["memory_id"] and e["target"] == proposal["evidence_id"] for e in graph_data["edges"])
        assert any(e["source"] == proposal["memory_id"] and e["target"] == f"assessment:{changed['decision_id']}" for e in graph_data["edges"])
        async def graph_links():
            from app.memory import memory_graph
            async with memory_graph(config) as graph:
                memory_edges = await graph.relations.list(from_entity=proposal["memory_id"], type="SUPPORTED_BY")
                influence = await graph.relations.list(from_entity=proposal["memory_id"], type="INFLUENCED")
                version_edges = await graph.relations.list(from_entity=f"ruleversion:{proposal['id']}", type="DERIVED_FROM")
                return memory_edges.items, influence.items, version_edges.items
        import asyncio
        memory_edges, influence, version_edges = asyncio.run(graph_links())
        assert any(edge.to_entity == proposal["evidence_id"] for edge in memory_edges)
        assert any(edge.to_entity == f"assessment:{changed['decision_id']}" for edge in influence)
        assert any(edge.to_entity == f"ruleproposal:{proposal['id']}" for edge in version_edges)
        assert client.post("/api/scenarios/benign/run").json()["assessment"]["classification"] == "benign"
        assert client.post("/api/scenarios/benign-shared/run").json()["assessment"]["classification"] == "benign"
        assert client.post("/api/scenarios/brute-force/run").json()["assessment"]["classification"] == "single_source_brute_force"
        assert client.post(f"/api/reviews/{proposal['id']}/approve", json=reviewer, headers=headers).status_code == 409
        challenged = client.post(f"/api/reviews/{proposal['id']}/challenge", json=reviewer, headers=headers)
        assert challenged.status_code == 200, challenged.text
        state = client.get("/api/reviews").json()
        assert state["proposals"][0]["status"] == "CHALLENGED"
        assert state["active_version"] is None
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "benign"
        verified = client.post(f"/api/reviews/{proposal['id']}/verify", json=reviewer, headers=headers)
        assert verified.status_code == 200, verified.text
        assert client.get("/api/reviews").json()["proposals"][0]["status"] == "VERIFIED"
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "distributed_credential_stuffing"
        undone = client.post(f"/api/reviews/{proposal['id']}/rollback", json=reviewer, headers=headers)
        assert undone.status_code == 200, undone.text
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "benign"
        assert len(client.get("/api/reviews").json()["history"]) == 5


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_rejection_does_not_enable_rule(monkeypatch):
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "token"}
    with TestClient(main.app) as client:
        decision = client.post("/api/scenarios/distributed/run").json()["assessment"]
        proposal = client.post("/api/scenarios/distributed/feedback", headers=headers, json={"decision_id": decision["decision_id"]}).json()
        result = client.post(f"/api/reviews/{proposal['id']}/reject", headers=headers, json={"actor": "analyst", "reason": "Insufficient evidence"})
        assert result.status_code == 200, result.text
        assert client.get("/api/reviews").json()["proposals"][0]["status"] == "REJECTED"
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "benign"
        assert client.post(f"/api/reviews/{proposal['id']}/approve", headers=headers, json={"actor": "analyst", "reason": "Retry"}).status_code == 409


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_new_version_and_rollback_preserve_predecessor(monkeypatch):
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "token"}
    reviewer = {"actor": "analyst", "reason": "reviewed"}
    with TestClient(main.app) as client:
        proposals = []
        for _ in range(2):
            decision = client.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
            proposal = client.post("/api/scenarios/distributed/feedback", headers=headers, json={"decision_id": decision["decision_id"]}).json()
            result = client.post(f"/api/reviews/{proposal['id']}/approve", headers=headers, json=reviewer)
            assert result.status_code == 200, result.text
            proposals.append(proposal)
        assert client.get("/api/reviews").json()["active_version"] == f"ruleversion:{proposals[1]['id']}"
        result = client.post(f"/api/reviews/{proposals[1]['id']}/rollback", headers=headers, json=reviewer)
        assert result.status_code == 200, result.text
        assert client.get("/api/reviews").json()["active_version"] == f"ruleversion:{proposals[0]['id']}"


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_custom_incident_feedback_uses_recorded_features(monkeypatch):
    from app.simulator import generate
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "token"}
    events = [e.model_copy(update={"scenario_id": "custom-case"}).model_dump(mode="json") for e in generate("held-out", 42)]
    payload = {"incident_id":"custom-case", "events":events}
    with TestClient(main.app) as client:
        assert client.post("/api/incidents/analyze", json=payload).status_code == 403
        response = client.post("/api/incidents/analyze", json=payload, headers=headers)
        assert response.status_code == 200, response.text
        assessment = response.json()["assessment"]
        assert assessment["classification"] == "benign"
        async def stored_events():
            import json
            from app.memory import memory_graph
            async with memory_graph(config) as graph:
                entity = await graph.entities.get("autheventbatch:" + assessment["decision_id"] + "-0")
                return json.loads(entity.properties["events"])
        import asyncio
        assert asyncio.run(stored_events())[0]["event_id"] == events[0]["event_id"]
        feedback = {"decision_id":assessment["decision_id"], "confirmed_label":"distributed_credential_stuffing", "reviewer":"analyst", "evidence_note":"Reviewed sanitized incident"}
        result = client.post("/api/incidents/custom-case/feedback", json=feedback, headers=headers)
        assert result.status_code == 200, result.text
        proposal = result.json()
        assert proposal["source"] == "reviewer attestation"
        assert proposal["rule"]["min_accounts"] == (assessment["features"]["distinct_accounts"] + 1) // 2
        assert proposal["rule"]["min_accounts"] != 12
        assert proposal["status"] == "UNDER_REVIEW"


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_failed_approval_does_not_activate_and_can_retry(monkeypatch):
    import app.lifecycle as lifecycle
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "token"}
    reviewer = {"actor": "analyst", "reason": "reviewed"}
    original = lifecycle.event
    async def fail_approval(graph, kind, *args, **kwargs):
        if kind == "APPROVED":
            raise OSError("simulated interruption")
        return await original(graph, kind, *args, **kwargs)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        decision = client.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
        proposal = client.post("/api/scenarios/distributed/feedback", headers=headers, json={"decision_id":decision["decision_id"]}).json()
        monkeypatch.setattr(lifecycle, "event", fail_approval)
        failed = client.post(f"/api/reviews/{proposal['id']}/approve", headers=headers, json=reviewer)
        assert failed.status_code == 500
        assert client.get("/api/reviews").json()["active_version"] is None
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "benign"
        monkeypatch.setattr(lifecycle, "event", original)
        retried = client.post(f"/api/reviews/{proposal['id']}/approve", headers=headers, json=reviewer)
        assert retried.status_code == 200, retried.text
        assert client.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "distributed_credential_stuffing"


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_missing_graph_evidence_fails_closed(monkeypatch):
    import asyncio
    from app.memory import memory_graph
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "token"})
    monkeypatch.setattr(main, "settings", config)
    headers = {"X-Reviewer-Token": "token"}
    with TestClient(main.app) as client:
        decision = client.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
        proposal = client.post("/api/scenarios/distributed/feedback", headers=headers, json={"decision_id": decision["decision_id"]}).json()
        response = client.post(f"/api/reviews/{proposal['id']}/approve", headers=headers, json={"actor":"analyst", "reason":"reviewed"})
        assert response.status_code == 200, response.text
        async def remove_test_link():
            async with memory_graph(config) as graph:
                edges = await graph.relations.list(from_entity=proposal["memory_id"], type="SUPPORTED_BY", to_entity=proposal["evidence_id"])
                assert edges.items
                await graph.relations.delete(edges.items[0].id)
        asyncio.run(remove_test_link())
        assert client.post("/api/scenarios/held-out/run").status_code == 503
