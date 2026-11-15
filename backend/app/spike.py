from app.config import get_settings
from app.graph import GraphStore

QUERY = "MATCH (i:Incident {external_id: $id})-[:USES_TECHNIQUE]->(t:AttackTechnique) RETURN i.external_id AS incident, t.name AS technique LIMIT 10"
ID = "foundation:incident:001"

def read_graph(session):
    return [record.data() for record in session.run(QUERY, id=ID)]

def main():
    graph = GraphStore(get_settings())
    try:
        with graph.driver.session() as session:
            if not read_graph(session):
                session.run("CREATE (i:Incident {id: 100001, external_id: $id, name: $incident_name})-[:USES_TECHNIQUE]->(t:AttackTechnique {id: 100002, external_id: $technique_id, name: $technique_name})", id=ID, incident_name="Distributed login attempts", technique_id="foundation:technique:001", technique_name="Credential stuffing").consume()
            rows = read_graph(session)
            assert rows == [{"incident": ID, "technique": "Credential stuffing"}], rows
            print("Verified incident-to-technique traversal:", rows)
    finally:
        graph.close()

if __name__ == "__main__":
    main()


