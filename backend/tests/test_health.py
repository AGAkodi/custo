from fastapi.testclient import TestClient
from app.main import app

class UnavailableGraph:
    def check(self):
        raise OSError("unavailable")
    def close(self):
        pass

class ReadyGraph(UnavailableGraph):
    def check(self):
        pass

def test_liveness_and_unavailable_readiness():
    with TestClient(app) as client:
        client.app.state.graph.close()
        client.app.state.graph = UnavailableGraph()
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/ready").status_code == 503

def test_ready_requires_successful_graph_query():
    with TestClient(app) as client:
        client.app.state.graph.close()
        client.app.state.graph = ReadyGraph()
        assert client.get("/ready").json() == {"status": "ready", "hydradb": "connected"}


def test_scenario_graph_failure_returns_unavailable(monkeypatch):
    import app.main as main

    async def fail(*args, **kwargs):
        raise OSError("database offline")

    monkeypatch.setattr(main, "retrieve_context", fail)
    with TestClient(app) as client:
        response = client.post("/api/scenarios/benign/run")
        assert response.status_code == 503
        assert "database offline" not in response.text
