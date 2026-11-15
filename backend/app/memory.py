"""SelfGraph-backed foundation operations over the configured HydraDB instance."""
from selfgraph import HydraDBStore, SelfGraph

from app.config import Settings


def memory_graph(settings: Settings) -> SelfGraph:
    store = HydraDBStore(
        settings.hydradb_uri,
        auth=(settings.hydradb_username, settings.hydradb_password),
        connection_timeout=3,
        connection_acquisition_timeout=3,
    )
    return SelfGraph(store=store, namespace=settings.graph_namespace, level="light")


async def seed_foundation(settings: Settings) -> None:
    async with memory_graph(settings) as graph:
        await graph.insert.facts({
            "entities": [
                {"id": "incident:foundation", "type": "Incident", "name": "Foundation incident"},
                {"id": "attacktechnique:credential-stuffing", "type": "AttackTechnique", "name": "Credential stuffing"},
            ],
            "relations": [{
                "from_entity": "incident:foundation", "type": "USES_TECHNIQUE",
                "to_entity": "attacktechnique:credential-stuffing",
            }],
        })


async def retrieve_context(settings: Settings, query: str) -> str:
    async with memory_graph(settings) as graph:
        result = await graph.retrieve(query)
        return result.context


async def record_assessment(settings: Settings, assessment) -> None:
    """Store a decision and its scenario relationship; labels remain hidden."""
    async with memory_graph(settings) as graph:
        await graph.insert.facts({
            "entities": [
                {"id": f"incident:{assessment.scenario_id}", "type": "Incident", "name": assessment.scenario_id},
                {"id": f"assessment:{assessment.decision_id}", "type": "Assessment", "name": f"Decision {assessment.decision_id}",
                 "properties": {"classification": assessment.classification, "confidence": assessment.confidence, "action": assessment.action, "assessment_json": assessment.model_dump_json()}},
            ],
            "relations": [{"from_entity": f"assessment:{assessment.decision_id}", "type": "ASSESSES", "to_entity": f"incident:{assessment.scenario_id}"}],
        })

        for memory_id in assessment.memory_influences:
            await graph.relations.create(memory_id, "INFLUENCED", f"assessment:{assessment.decision_id}")
        for rule_id in assessment.matched_rules:
            if rule_id.startswith("ruleversion:"):
                await graph.relations.create(rule_id, "INFLUENCED", f"assessment:{assessment.decision_id}")


async def record_custom_events(settings: Settings, assessment, events) -> None:
    """Persist sanitized custom event batches and links to their assessment."""
    import json
    async with memory_graph(settings) as graph:
        for offset in range(0, len(events), 20):
            batch_id = f"autheventbatch:{assessment.decision_id}-{offset // 20}"
            payload = json.dumps([event.model_dump(mode="json") for event in events[offset:offset + 20]])
            await graph.entities.create(f"Event batch {assessment.decision_id}-{offset // 20}", "AuthEventBatch", id=batch_id, properties={"events": payload, "decision_id": assessment.decision_id})
            await graph.relations.create(batch_id, "EVIDENCE_FOR", f"assessment:{assessment.decision_id}")
