import csv
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")

def import_data(uri, auth):
    print(f"Connecting to Neo4j at {uri}...")
    with GraphDatabase.driver(uri, auth=auth) as driver:
        with driver.session() as session:
            print("Creating Constraints...")
            try:
                session.run("CREATE CONSTRAINT mitre_entity_id IF NOT EXISTS FOR (n:MITRE_Entity) REQUIRE n.id IS UNIQUE")
            except Exception as e:
                print("Could not create constraint (may already exist):", e)
                
            print("Importing Nodes...")
            with open('mitre_nodes.csv', 'r') as f:
                reader = csv.DictReader(f)
                nodes_batch = []
                for row in reader:
                    nodes_batch.append(row)
                    if len(nodes_batch) >= 1000:
                        session.execute_write(create_nodes, nodes_batch)
                        nodes_batch = []
                if nodes_batch:
                    session.execute_write(create_nodes, nodes_batch)
            
            print("Importing Edges...")
            with open('mitre_edges.csv', 'r') as f:
                reader = csv.DictReader(f)
                edges_batch = []
                for row in reader:
                    edges_batch.append(row)
                    if len(edges_batch) >= 1000:
                        session.execute_write(create_edges, edges_batch)
                        edges_batch = []
                if edges_batch:
                    session.execute_write(create_edges, edges_batch)
            
            # Post-processing to add specific labels based on the 'type' property
            print("Applying specific labels to nodes...")
            types = session.run("MATCH (n:MITRE_Entity) RETURN DISTINCT n.type AS type").value()
            for t in types:
                if t:
                    session.run(f"MATCH (n:MITRE_Entity {{type: '{t}'}}) SET n:{t}")

            print("Import Complete!")

def create_nodes(tx, nodes_batch):
    query = """
    UNWIND $batch AS row
    MERGE (n:MITRE_Entity {id: row.id})
    SET n.name = row.name,
        n.description = row.description,
        n.url = row.url,
        n.type = row.type
    """
    tx.run(query, batch=nodes_batch)

def create_edges(tx, edges_batch):
    rels = {}
    for edge in edges_batch:
        rel_type = edge['relationship_type']
        if rel_type not in rels:
            rels[rel_type] = []
        rels[rel_type].append(edge)
    
    for rel_type, batch in rels.items():
        query = f"""
        UNWIND $batch AS row
        MATCH (source:MITRE_Entity {{id: row.source_id}})
        MATCH (target:MITRE_Entity {{id: row.target_id}})
        MERGE (source)-[r:`{rel_type}`]->(target)
        """
        tx.run(query, batch=batch)

if __name__ == "__main__":
    import_data(URI, AUTH)
