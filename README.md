# Custos



A security intelligence laboratory for learning from confirmed incidents through a persistent graph. The local demo includes the simulator, baseline detector, review-controlled lifecycle, graph explorer, and held-out evaluation.



## Local development



Requires Python 3.12 and Node.js. From the repository root copy `.env.example` to `.env`, and configure a real HydraDB Bolt endpoint and credentials. Do not commit secrets. For the local database, set a long random `HYDRADB_PASSWORD` in `.env`, then run `docker compose up -d` from the repository root. Docker Desktop or Docker Engine must be running. The local container stores data in a named volume and exposes ports only on localhost. The plaintext connection is for local development only.



In a terminal, from `backend`:



```

python -m venv .venv

# Windows: .venv\Scripts\activate; macOS/Linux: source .venv/bin/activate

python -m pip install -r requirements-dev.txt

uvicorn app.main:app --reload

```



In another terminal, from `frontend`:



```

npm install

npm run dev

```



Open the Vite URL. Seed the sample graph from `backend` with `python -m app.seed`. `GET /api/foundation/context` retrieves it through SelfGraph. `GET /health` is liveness; `GET /ready` performs a graph query and returns 503 when HydraDB is unavailable. API docs are at `/docs`. To test: `python -m pytest` in backend and `npm run build` in frontend.



## Foundation status



The pinned local HydraDB image and SelfGraph 0.2.1 have passed graph insertion, retrieval, and a read after restart. Run `python -m app.seed` to seed the example. To run integration tests, set `CUSTOS_INTEGRATION=1` and run `python -m pytest` from `backend`; these tests write the named foundation graph. The general lifecycle and concurrency-safe rule/version operations are later-phase work. See [integration notes](docs/hydradb-spike.md).





## Phase 2: simulator and baseline



With HydraDB and the backend running, open `/docs` for the API. `GET /api/scenarios` lists eight reproducible fixtures. `POST /api/scenarios/{id}/run` returns fictional events, extracted features, a structured assessment, and stores the assessment and incident relationship in HydraDB. `POST /api/scenarios/run-batch` analyzes all eight with the configured `DEMO_SEED`. Labels are omitted from run responses; `POST /api/scenarios/{id}/reveal` explicitly returns a synthetic fixture label. The `held-out` case is reserved for later evaluation and must not be used as feedback.



The baseline uses a ten-minute densest window: at least ten failures from one IP flags brute force; a success after at least three failures for the same account escalates. The distributed rule is intentionally absent. The resulting `benign` classification means no baseline rule matched, not verified safety; confidence values are fixed illustrative scores, not calibrated probabilities. Retrieved graph context is recorded but does not influence phase 2 decisions. Each run creates a new decision; the batch endpoint is not atomic and partial results can remain if a graph write fails.



All data is synthetic, and results are not claims of real-world detection accuracy. Run the graph-backed tests as described above; the test suite checks reproducibility, validation, baseline cases, graph failures, persisted assessment data, and batch behavior.





## Phase 3: review-controlled learning



Set a long random `REVIEWER_TOKEN` in the ignored root `.env` and restart the backend. Review and feedback endpoints require that value in the `X-Reviewer-Token` request header; if it is unset, writes are disabled. This is a local demo credential, not production authentication. Do not expose the API publicly with this arrangement. Use `/docs` or an HTTP client to run the sequence:



1. Run `POST /api/scenarios/distributed/run?baseline=true` and copy its `assessment.decision_id`. The frozen baseline should classify this fixture as benign (no rule match).

2. Submit `POST /api/scenarios/distributed/feedback` with `{"decision_id":"<id>"}` and the reviewer header. This explicitly confirms the synthetic label and creates evidence, a proposed memory, and a structured rule. It rejects held-out scenarios as feedback.

3. Inspect `GET /api/reviews` for the proposal, its two benign regression results, and lifecycle history. Approve with `POST /api/reviews/{proposal_id}/approve` using `{"actor":"analyst","reason":"Reviewed evidence and regression results"}` and the same header. Rejection is available at `/reject`.

4. Run `POST /api/scenarios/held-out/run` and inspect the rule and memory references in the assessment. Compare with `?baseline=true`. The original brute-force rule remains active.

5. A reviewer can call `/challenge` with actor and reason to attach an unverified conflicting report and suspend the active version. `/verify` records a reviewer decision to restore the challenged version; `/rollback` restores the preceding approved version or the baseline. These actions retain history.



The candidate is a constrained distributed-login rule whose thresholds are derived from the recorded incident features, not generated code. The threshold fractions are fixed heuristics, not statistical learning. Approval requires a feedback match and no matches on the two bundled benign controls. One labeled incident and two controls are insufficient to establish real-world accuracy. A similar benign distributed pattern could still be flagged. Scores remain illustrative, and the API does not change firewalls or perform live response.



The graph stores the incident assessment, confirmed fixture evidence, memory proposal, immutable rule-version entity, review events, and influence relationships. Current proposal status is derived from append-only lifecycle events. The reviewer's verification is a recorded human assertion, not independent validation of a report.



**Demo limitation:** lifecycle transitions use an in-process lock and multiple graph operations rather than a single atomic transaction. Run one backend worker; do not use this implementation for concurrent or production approvals. A failure during a transition can leave incomplete graph records and may require manual inspection. Feedback accepts bundled fixtures and reviewer-attested sanitized custom incidents for the supported distributed-login family. The local service now uses non-root execution and fail-closed lifecycle commit markers, but generalized contradictions, atomic transactions and production-grade concurrency remain future work.





## Local dashboard



Start HydraDB with `docker compose up -d`, the backend from `backend` with `uvicorn app.main:app`, and the frontend from `frontend` with `npm run dev`. Open the URL printed by Vite (normally http://localhost:5173). The dev server proxies `/api` to port 8000. The lifecycle review actions require the local `REVIEWER_TOKEN` from `.env`, entered in the UI for the current page session.



The evaluation compares the same twelve seeded held-out incidents and stores results in HydraDB. Its benign overlap deliberately matches the learned rule, so a successful adaptive detection also produces a false positive in this sample. See [evaluation methodology](docs/evaluation.md) and [demo script](docs/demo-script.md).



The project is currently local-only. In Lifecycle review, enter the reviewer token and select **Reset demo** to start a new isolated demo namespace. Previous graph data is retained rather than deleted, and the chosen namespace persists across backend restarts. Reset is restricted to a local development database. The [recorded local demo](docs/media/custos-demo.webm) is a silent 28-second browser recording; it is not a narrated submission video.



### Browser and accessibility tests



Install frontend packages with `npm ci` and the Playwright video encoder with `npx playwright install ffmpeg`. The tests use installed Chrome and require the local frontend and an **isolated test backend** at ports 5173 and 8000. Start the backend from `backend` with `GRAPH_NAMESPACE=custos_e2e_initial`, `CUSTOS_RUNTIME_DIR` set to a dedicated writable test directory, and `REVIEWER_TOKEN` set to a test-only value. Start Vite from `frontend`, then set `CUSTOS_E2E_TOKEN` to that same test-only value and run `npm run test:e2e`. The test performs resets, approves a simulated rule, verifies held-out results and graph links, reloads the evaluation, and runs axe scans at desktop and mobile sizes. Do not run it against a non-test demo server: it changes that server's current namespace. Public deployment remains deferred.



## Phase 5: data and SOC

Open **Data & SOC** to analyze a small UNSW-NB15 or CICIDS2017 flow CSV, download the experimental baseline Sigma correlation bundle, or preview an assessment for optional Splunk HEC delivery. Two invented schema samples are in `backend/fixtures`. Actual datasets, compatible Splunk configuration, credentials, and explicit delivery are separate. See [phase 5 details](docs/phase5.md) for schemas, limitations, thresholds, Sigma approximation, and privacy behavior.


## Audit improvements

Held-out authentication fixtures now use source IPs and account IDs disjoint from feedback, and the evaluation uses four distinct seeds per scenario family. Active rule use checks graph provenance and feature similarity against the evidence-backed memory. A reviewer can submit sanitized custom authentication events in Data & SOC or via the API; a fictional [example](backend/fixtures/custom-incident.example.json) is provided. See [lifecycle details](docs/lifecycle.md). Only distributed-credential-stuffing proposals are supported, and heuristic thresholds still require review.

The HydraDB service runs as UID 10001 with dropped capabilities after a one-shot volume initialization. Its development Bolt endpoint remains plaintext and bound to localhost; this is not a production security configuration. SelfGraph's transaction wrapper does not make the multi-operation lifecycle transition atomic. A failed transition can leave inactive partial graph records; the commit marker prevents an unlinked event from activating a rule and approvals can be retried, but this does not provide distributed consistency. The prior paid hosted MCP service is not needed by the application; the upstream local MCP has not been verified against this graph.
