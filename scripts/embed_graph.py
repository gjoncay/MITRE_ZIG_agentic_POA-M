import json
import os
import sys

# Add scripts directory to path to import graph_engine
sys.path.append(os.path.dirname(__file__))
from graph_engine import KnowledgeGraphEngine

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("Error: sentence-transformers or numpy not installed. Cannot generate embeddings.")
    sys.exit(1)

def embed_graph_nodes():
    engine = KnowledgeGraphEngine()
    
    print("Loading embedding model (all-MiniLM-L6-v2)...")
    # Using a small, fast local model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    node_ids = []
    texts_to_embed = []
    
    print(f"Preparing {engine.graph.number_of_nodes()} nodes for embedding...")
    for n, data in engine.graph.nodes(data=True):
        name = data.get('name', '')
        desc = data.get('description', '')

        # Skip attribute-less nodes; embedding empty text pollutes search results
        if not name and not desc:
            continue

        # Combine name and description for semantic context
        text = f"{name}. {desc}"
        node_ids.append(n)
        texts_to_embed.append(text)
        
    print("Generating embeddings (this may take a minute)...")
    # --- EXTERNAL API SCAFFOLDING ---
    # If using an Agency API instead of a local model:
    # api_embeddings = []
    # for text in texts_to_embed:
    #     api_embeddings.append(call_agency_api(text))
    # embeddings = np.array(api_embeddings)
    # --------------------------------
    
    embeddings = model.encode(texts_to_embed, show_progress_bar=True)
    
    # Save the embeddings
    npz_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'graph_embeddings.npz')
    np.savez(npz_path, embeddings=embeddings)
    
    # Save the metadata (mapping array index to node id)
    meta_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'embedding_metadata.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump({"node_ids": node_ids}, f)
        
    print(f"Successfully saved embeddings to {npz_path} and metadata to {meta_path}")

if __name__ == "__main__":
    embed_graph_nodes()
