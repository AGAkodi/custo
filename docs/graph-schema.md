# Graph schema

Custos uses SelfGraph entities in the configured namespace. `Incident` and `Assessment` nodes record a scenario and each decision. `IncidentEvidence` records the confirmed fixture outcome and event IDs; `ThreatMemory` records the proposed behavioral lesson; `RuleProposal` contains the structured thresholds and regression summary. Approval creates a `RuleVersion`. `LifecycleEvent` nodes preserve proposed, approved, rejected, challenged, verified, and rollback actions. `ChallengeEvidence` records unverified reviewer reports. `EvaluationRun` stores a measured held-out comparison.

Key relationships: `Assessment -[:ASSESSES]-> Incident`; `IncidentEvidence -[:SUPPORTS_REVIEW_OF]-> Assessment`; `ThreatMemory -[:SUPPORTED_BY]-> IncidentEvidence`; `RuleProposal -[:DERIVED_FROM]-> ThreatMemory`; `RuleVersion -[:DERIVED_FROM]-> RuleProposal` and `-[:SUPPORTED_BY]-> IncidentEvidence`; `ThreatMemory` and `RuleVersion -[:INFLUENCED]-> Assessment`; newer rule versions may `SUPERSEDES` earlier ones; challenge evidence `CONTRADICTS` a memory.

`GET /api/graph/neighborhood` exposes a bounded selection of actual stored nodes and relationships. Integration tests check the evidence, version and influence links against the running database. For query engine limitations and verified connection details see [the integration spike](hydradb-spike.md).
