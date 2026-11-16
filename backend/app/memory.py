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


async def related_incidents(settings, features, limit=5):
    """Rank evidence-backed prior incidents; unreviewed memories do not drive a decision."""
    import json
    from app.types import Features

    dimensions = ("failures", "distinct_ips", "distinct_accounts", "max_failures_per_ip")
    async with memory_graph(settings) as graph:
        page = await graph.entities.list(type="ThreatMemory", limit=100)
        candidates = []
        for memory in page.items:
            signature = memory.properties.get("feature_signature")
            if not signature:
                continue
            reference = Features.model_validate_json(signature)
            comparisons = {}
            for name in dimensions:
                observed, prior = getattr(features, name), getattr(reference, name)
                comparisons[name] = round(min(observed, prior) / max(observed, prior), 4) if max(observed, prior) else 1.0
            links = await graph.relations.list(from_entity=memory.id, type="SUPPORTED_BY", limit=30)
            for edge in links.items:
                evidence = await graph.entities.get(edge.to_entity)
                if not evidence or evidence.type != "IncidentEvidence":
                    continue
                decision_id = evidence.properties.get("decision_id")
                if not decision_id:
                    continue
                source_id = "assessment:" + decision_id
                provenance = await graph.relations.list(from_entity=edge.to_entity, type="SUPPORTS_REVIEW_OF", to_entity=source_id, limit=1)
                source = await graph.entities.get(source_id)
                if not provenance.items or not source:
                    continue
                prior = json.loads(source.properties["assessment_json"])
                candidates.append({"memory_id": memory.id, "evidence_id": evidence.id,
                                   "incident_id": prior["scenario_id"], "decision_id": decision_id,
                                   "confirmed_label": evidence.properties.get("label"),
                                   "similarity": round(sum(comparisons.values()) / len(comparisons), 4),
                                   "comparisons": comparisons,
                                   "note": "Related evidence; relevance is not proof of maliciousness or approval."})
                break
        return sorted(candidates, key=lambda item: (-item["similarity"], item["memory_id"]))[:limit]


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
