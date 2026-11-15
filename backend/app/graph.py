"""HydraDB Bolt connection. Queries must be verified against the deployed version."""
from neo4j import GraphDatabase
from app.config import Settings

class GraphStore:
    def __init__(self, settings: Settings):
        self.driver = GraphDatabase.driver(
            settings.hydradb_uri,
            auth=(settings.hydradb_username, settings.hydradb_password),
            connection_timeout=3,
            connection_acquisition_timeout=3,
        )

    def check(self) -> None:
        with self.driver.session() as session:
            session.run("MATCH (n:Incident) RETURN n.id AS id LIMIT 1").consume()

    def close(self) -> None:
        self.driver.close()


