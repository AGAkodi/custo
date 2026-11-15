# HydraDB integration spike

Docker Desktop runs the official HydraDB image pinned by digest in `docker-compose.yml` (build branch v0.4.0, commit 916637477f3f34766b4905b270bd4292109d77e6). The local-only Bolt endpoint is `127.0.0.1:17687`; graph data is stored in a Docker named volume. The generated local token is in the ignored `.env`. Anonymous usage reporting is disabled in the compose configuration.

Verified against the running instance: a property-based readiness read; parameterized CREATE of an Incident linked to an AttackTechnique; a parameterized traversal; and a read-only traversal after restarting the container. `python -m app.spike` reproduces the graph check. Its read-before-create guard is not concurrency-safe; do not treat it as an upsert implementation.

Compatibility findings: this version rejected `RETURN 1`, a node-only MERGE and MERGE followed by SET. CREATE required integer node `id` properties, so the test stores application identifiers separately as `external_id`. Further query and transactional behavior must be verified before designing a general adapter.

SelfGraph 0.2.1 was tested with `HydraDBStore(uri, auth=(username, password))` and `SelfGraph(store=store, namespace="custos", level="light")`. `graph.insert.facts(...)` and `graph.retrieve(...)` succeeded, including retrieval after database restart. Inserting the same sample twice remains retrievable, but this is not a proof of concurrency-safe upsert. `app.memory` contains the current adapter and the opt-in integration test checks the API against the real database.

The local lifecycle now stores versioned proposals, evidence, decisions and review events. Its commit-marker recovery is fail-closed but is not an atomic transaction or a distributed lock. Application upserts and multi-worker writes remain unverified.

Upstream: https://github.com/hydra-db/hydradb and https://github.com/hydra-db/selfgraph


## Local MCP compatibility investigation

The pinned image contains `graph-node`, `graph-indexer` and `falkor-dump-import`, but no `hydradb-mcp` binary. The matching upstream source does contain a Rust stdio MCP server that can connect to an existing authenticated HTTP node. Its `execute_query` requires tenant and subtenant and appends their encoded identifiers to the configured graph namespace. Custos currently uses SelfGraph against the default Bolt database and its own SelfGraph namespace. Those scoping models have not been demonstrated to address the same stored graph; no MCP was registered or pointed at your data. Building the upstream component and proving scope compatibility or planning an explicit migration remain separate work. The current Custos app does not need an MCP server or hosted account.

Reference: https://github.com/hydra-db/hydradb/blob/916637477f3f34766b4905b270bd4292109d77e6/crates/mcp/README.md
