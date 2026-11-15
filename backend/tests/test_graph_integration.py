"""Opt-in integration test: requires the local persistent HydraDB container."""
import asyncio
import os

import pytest

from app.config import get_settings
from app.memory import retrieve_context, seed_foundation


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_real_graph_seed_and_retrieval():
    async def check():
        settings = get_settings()
        await seed_foundation(settings)
        await seed_foundation(settings)
        context = await retrieve_context(settings, "Foundation incident")
        assert "Foundation incident" in context
        assert "Credential stuffing" in context
        assert "USES_TECHNIQUE" in context
    asyncio.run(check())


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_api_reads_persisted_graph():
    from fastapi.testclient import TestClient
    from app.main import app

    asyncio.run(seed_foundation(get_settings()))
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200
        response = client.get("/api/foundation/context")
        assert response.status_code == 200
        assert "USES_TECHNIQUE" in response.json()["context"]


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_scenario_run_persists_decision():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.memory import retrieve_context

    with TestClient(app) as client:
        response = client.post("/api/scenarios/distributed/run")
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["assessment"]["classification"] == "benign"
        assert "confirmed_label" not in response.text
        decision_id = data["assessment"]["decision_id"]
        context = asyncio.run(retrieve_context(get_settings(), f"Decision {decision_id}"))
        assert decision_id in context
        assert "ASSESSES" in context
        async def read_decision():
            from app.memory import memory_graph
            async with memory_graph(get_settings()) as graph:
                return await graph.entities.get(f"assessment:{decision_id}")
        entity = asyncio.run(read_decision())
        assert entity is not None
        assert '"evidence_event_ids"' in entity.properties["assessment_json"]
        assert entity.properties["classification"] == "benign"
        assert client.post("/api/scenarios/distributed/reveal").json()["confirmed_label"] == "distributed_credential_stuffing"


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_batch_analyzes_all_scenarios_without_labels():
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        result = client.post("/api/scenarios/run-batch")
        assert result.status_code == 200, result.text
        assert len(result.json()["results"]) == 8
        assert "confirmed_label" not in result.text
