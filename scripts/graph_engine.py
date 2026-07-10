import csv
import networkx as nx

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    import json
    import os
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False

class KnowledgeGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.load_data()
        
        self.semantic_enabled = SEMANTIC_ENABLED
        self.embedding_model = None
        self.embeddings = None
        self.embedding_node_ids = None
        
        if self.semantic_enabled:
            self._load_embeddings()

    def _load_embeddings(self):
        try:
            # Look in the parent directory where the main scripts run
            base_dir = os.path.dirname(os.path.dirname(__file__))
            npz_path = os.path.join(base_dir, 'graph_embeddings.npz')
            meta_path = os.path.join(base_dir, 'embedding_metadata.json')
            
            if os.path.exists(npz_path) and os.path.exists(meta_path):
                self.embeddings = np.load(npz_path)['embeddings']
                with open(meta_path, 'r', encoding='utf-8') as f:
                    self.embedding_node_ids = json.load(f)['node_ids']
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                self.semantic_enabled = False
        except Exception as e:
            print(f"Failed to load semantic model/embeddings: {e}")
            self.semantic_enabled = False

    def load_data(self):
        # Load MITRE Data
        try:
            with open('mitre_nodes.csv', 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    self.graph.add_node(row['id'], **row)
            with open('mitre_edges.csv', 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])
        except Exception as e:
            print(f"Error loading MITRE data: {e}")

        # Load ZIG Data
        try:
            with open('zig_nodes.csv', 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    self.graph.add_node(row['id'], **row)
            with open('zig_edges.csv', 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])
        except Exception as e:
            print(f"Error loading ZIG data: {e}")
            
        print(f"Knowledge Graph initialized with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")

    def query_node(self, node_id):
        """Returns the attributes of a specific node."""
        if self.graph.has_node(node_id):
            return self.graph.nodes[node_id]
        return None

    def search_nodes(self, keyword, exact_match=False):
        """Searches node IDs, Names, or Descriptions for a keyword."""
        results = []
        keyword = keyword.lower()
        for n, data in self.graph.nodes(data=True):
            if exact_match:
                if keyword == str(n).lower() or keyword == str(data.get('name', '')).lower():
                    results.append((n, data))
            else:
                if (keyword in str(n).lower() or 
                    keyword in str(data.get('name', '')).lower() or 
                    keyword in str(data.get('description', '')).lower()):
                    results.append((n, data))
        return results

    def semantic_search(self, query_text, top_k=3):
        """Performs a semantic vector search if enabled, else falls back to keyword search."""
        if not self.semantic_enabled or self.embeddings is None:
            print("[Warning] Semantic search unavailable. Falling back to keyword search.")
            return self.search_nodes(query_text)[:top_k]
            
        # Embed the query
        query_vec = self.embedding_model.encode([query_text])
        
        # Calculate cosine similarity
        similarities = cosine_similarity(query_vec, self.embeddings)[0]
        
        # Get top K indices
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            node_id = self.embedding_node_ids[idx]
            if self.graph.has_node(node_id):
                results.append((node_id, self.graph.nodes[node_id], float(similarities[idx])))
                
        return results

    def get_neighbors(self, node_id, direction='both'):
        """Gets immediate neighbors of a node."""
        if not self.graph.has_node(node_id):
            return []
            
        neighbors = []
        if direction in ['out', 'both']:
            for target in self.graph.successors(node_id):
                edge_data = self.graph.get_edge_data(node_id, target)
                neighbors.append({'id': target, 'direction': 'out', 'relationship': edge_data.get('relationship')})
        if direction in ['in', 'both']:
            for source in self.graph.predecessors(node_id):
                edge_data = self.graph.get_edge_data(source, node_id)
                neighbors.append({'id': source, 'direction': 'in', 'relationship': edge_data.get('relationship')})
                
        return neighbors

    def crawl_subgraph(self, start_node_id, depth=2):
        """Returns a list of nodes and edges representing the crawled subgraph up to a certain depth."""
        if not self.graph.has_node(start_node_id):
            return {"error": "Node not found"}
            
        # Extract ego graph (subgraph of neighbors up to a certain radius)
        # Using undirected distance so we can crawl forwards and backwards
        subgraph = nx.ego_graph(self.graph.to_undirected(), start_node_id, radius=depth)
        
        # Now we extract the directed edges that exist in the original graph for these nodes
        nodes_data = {n: self.graph.nodes[n] for n in subgraph.nodes()}
        edges_data = []
        
        for u, v in self.graph.edges(subgraph.nodes()):
            if v in subgraph.nodes():
                edge_info = self.graph.get_edge_data(u, v)
                edges_data.append({
                    "source": u,
                    "target": v,
                    "relationship": edge_info.get("relationship", "")
                })
                
        return {
            "start_node": start_node_id,
            "depth_crawled": depth,
            "nodes": nodes_data,
            "edges": edges_data
        }

if __name__ == "__main__":
    engine = KnowledgeGraphEngine()
    # Simple test
    print("\nTest: Querying a ZIG Pillar")
    print(engine.query_node("ZIG-PIL-1"))
    
    print("\nTest: Querying a MITRE node (e.g. T1548)")
    print(engine.query_node("T1548"))
