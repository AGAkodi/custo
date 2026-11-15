import asyncio
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.config as config
import app.main as main
from app.memory import memory_graph


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_reset_is_scoped_persistent_and_protected(monkeypatch, tmp_path):
    namespace = "test_" + uuid4().hex
    settings = main.settings.model_copy(update={"graph_namespace": namespace, "reviewer_token": "test-token", "app_env": "development"})
    monkeypatch.setattr(main, "settings", settings)
    monkeypatch.setattr(config, "RUNTIME_DIR", tmp_path)
    monkeypatch.setattr(config, "SESSION_FILE", tmp_path / "demo-session.json")
    with TestClient(main.app) as client:
        previous = client.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
        assert client.post("/api/demo/reset").status_code == 403
        response = client.post("/api/demo/reset", headers={"X-Reviewer-Token": "test-token"})
        assert response.status_code == 200, response.text
        assert response.json()["namespace"].startswith("custos_demo_")
        assert client.get("/api/reviews").json()["proposals"] == []
        assert client.get("/api/evaluation/latest").json() is None
        async def find_old():
            old = settings.model_copy(update={"graph_namespace": namespace})
            async with memory_graph(old) as graph:
                return await graph.entities.get("assessment:" + previous["decision_id"])
        assert asyncio.run(find_old()) is not None
        config.get_settings.cache_clear()
        try:
            assert config.get_settings().graph_namespace == response.json()["namespace"]
        finally:
            config.get_settings.cache_clear()
        settings.hydradb_uri = "bolt://remote.example:7687"
        assert client.post("/api/demo/reset", headers={"X-Reviewer-Token": "test-token"}).status_code == 403
        settings.app_env = "production"
        assert client.post("/api/demo/reset", headers={"X-Reviewer-Token": "test-token"}).status_code == 403
