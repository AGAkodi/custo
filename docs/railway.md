# Railway demo deployment

Deploy two services from this repository in the same Railway project and environment. This is a shared-password demo, not a production security deployment. Use fictional data and one replica per service.

## HydraDB service

1. Add a GitHub service named `hydradb`, using this repository and the same branch as the web service. Set **Dockerfile Path** to `/deploy/hydradb.Dockerfile`.
2. Add a volume mounted at `/data`. Set `RAILWAY_RUN_UID=0`: the startup script prepares the root-owned volume then starts HydraDB as the unprivileged `graph` user. The volume is mounted at runtime, not during build.
3. Set `HYDRADB_PASSWORD` to a randomly generated value of at least 32 non-placeholder characters. Treat it as a secret. Do not add a public domain or TCP proxy to this service.

## Web service

1. Add another GitHub service from this repository, using the root `/Dockerfile`.
2. Set `APP_ENV=production`, `HYDRADB_URI=bolt://hydradb.railway.internal:7687`, `HYDRADB_USERNAME=neo4j`, and `HYDRADB_PASSWORD` to the same value as the database service. Use Railway variable references if available.
3. Set `DEMO_USERNAME` and a strong `DEMO_PASSWORD`. All pages and API endpoints except `/health` require these credentials. Set a separate strong `REVIEWER_TOKEN` to enable review actions.
4. Generate a Railway public domain for the web service only. Set the health check to `/health` and keep one replica and one Uvicorn worker.
5. Visit the HTTPS domain and authenticate. Check `/ready` while authenticated, then run a demo scenario and inspect the graph. Restart the HydraDB service and verify graph data survives. Set up and test a backup of the volume.

The local reset endpoint is intentionally disabled in this deployment. The existing reset button will return an error; a hosted reset and per-judge isolation have not been implemented. Review changes affect the shared graph for everyone. Railway's monthly charge depends on actual resource use and plan. The Docker image pins the same HydraDB build used locally; verify availability and service networking in the target environment.
