# Air-Gapped Deployment Guide & Agent Reconstruction Plan
> **Prompt Instruction for Claude 3.5 Sonnet / Claude Code (Top Secret Environment):**
> *You are tasked with recreating a Python-based NetworkX Graph Database that integrates MITRE ATT&CK/D3FEND and NSA Zero Trust (ZIG) mappings. Your primary goal is to build an engine that LLM Agents can query programmatically to map unstructured threat intelligence to actionable Zero Trust capability plans. You must implement the Python files exactly as outlined in this document.*

---

## 1. Architectural Context & Graceful Degradation
This repository features a **Graceful Degradation Architecture** designed specifically for high-security, air-gapped environments. 
- The engine uses **Vector Embeddings (Semantic Search)** to map messy threat intelligence (e.g. "attackers dumped hashes") to formal frameworks without requiring exact keywords.
- **HOWEVER**, if machine learning libraries (`sentence-transformers`, `numpy`) cannot be pushed to the high side, the engine is designed to seamlessly catch the `ImportError`, disable semantic search, and automatically route all queries through an **Exact Keyword Matching** fallback. It will not crash.

---

## 2. Directory Structure Setup
Claude, begin by ensuring the following directory structure exists:
```text
/MITRE_CSD-H/
├── mitre_nodes.csv
├── mitre_edges.csv
├── zig_nodes.csv
├── zig_edges.csv
├── assessment_template.md
├── agent_crawl_example.py
└── scripts/
    ├── graph_engine.py
    └── embed_graph.py
```

---

## 3. Code Implementation: The Graph Engine
Create the file `scripts/graph_engine.py`. This is the core logic. Notice the `try/except` block at the top which handles the air-gapped library limitations.

```python
import csv
import networkx as nx
import os
import json

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
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
        base_dir = os.path.dirname(os.path.dirname(__file__))
        
        # Load MITRE Data
        with open(os.path.join(base_dir, 'mitre_nodes.csv'), 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                self.graph.add_node(row['id'], **row)
        with open(os.path.join(base_dir, 'mitre_edges.csv'), 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])

        # Load ZIG Data
        with open(os.path.join(base_dir, 'zig_nodes.csv'), 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                self.graph.add_node(row['id'], **row)
        with open(os.path.join(base_dir, 'zig_edges.csv'), 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])

    def query_node(self, node_id):
        if self.graph.has_node(node_id):
            return self.graph.nodes[node_id]
        return None

    def search_nodes(self, keyword, exact_match=False):
        """Fallback keyword search if Semantic search is unavailable."""
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
        """Performs a semantic vector search if enabled, else routes to keyword search."""
        if not self.semantic_enabled or self.embeddings is None:
            print("[Warning] ML Libraries missing. Routing to Exact Keyword Search...")
            results = self.search_nodes(query_text)[:top_k]
            # Standardize return format to match semantic search (id, data, dummy_score)
            return [(res[0], res[1], 1.0) for res in results]
            
        query_vec = self.embedding_model.encode([query_text])
        similarities = cosine_similarity(query_vec, self.embeddings)[0]
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            node_id = self.embedding_node_ids[idx]
            if self.graph.has_node(node_id):
                results.append((node_id, self.graph.nodes[node_id], float(similarities[idx])))
                
        return results

    def crawl_subgraph(self, start_node_id, depth=2):
        if not self.graph.has_node(start_node_id): return None
        subgraph = nx.ego_graph(self.graph.to_undirected(), start_node_id, radius=depth)
        nodes_data = {n: self.graph.nodes[n] for n in subgraph.nodes()}
        edges_data = []
        for u, v in self.graph.edges(subgraph.nodes()):
            if v in subgraph.nodes():
                edge_info = self.graph.get_edge_data(u, v)
                edges_data.append({"source": u, "target": v, "relationship": edge_info.get("relationship", "")})
        return {"start_node": start_node_id, "depth_crawled": depth, "nodes": nodes_data, "edges": edges_data}
```

---

## 4. Code Implementation: Generating Embeddings
Create `scripts/embed_graph.py`. If Python ML libraries *are* successfully ported to the secure network, you must run this script once to generate the `.npz` vector matrix based on your framework CSVs.

```python
import json
import os
import sys

sys.path.append(os.path.dirname(__file__))
from graph_engine import KnowledgeGraphEngine

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("Cannot run embed_graph.py. Machine Learning libraries are not installed.")
    sys.exit(1)

def embed_graph_nodes():
    engine = KnowledgeGraphEngine()
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    node_ids = []
    texts_to_embed = []
    
    for n, data in engine.graph.nodes(data=True):
        text = f"{data.get('name', '')}. {data.get('description', '')}"
        node_ids.append(n)
        texts_to_embed.append(text)
        
    embeddings = model.encode(texts_to_embed, show_progress_bar=True)
    
    base_dir = os.path.dirname(os.path.dirname(__file__))
    np.savez(os.path.join(base_dir, 'graph_embeddings.npz'), embeddings=embeddings)
    
    with open(os.path.join(base_dir, 'embedding_metadata.json'), 'w', encoding='utf-8') as f:
        json.dump({"node_ids": node_ids}, f)

if __name__ == "__main__":
    embed_graph_nodes()
```

---

## 5. Code Implementation: The Markdown Template
Create `assessment_template.md`. This forces the Agent to output structured formats.

```markdown
# Threat & Mitigation Assessment Report

**Date:** {DATE}
**Assessment ID:** {ASSESSMENT_ID}

---

## 1. Executive Summary
**Finding / Threat Input:** {THREAT_INPUT_SUMMARY}

### 🚨 Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** {EXPLOITATION_SCENARIO}
- **Potential Impact:** {BUSINESS_IMPACT}

---

## 2. MITRE Framework Analysis
### ATT&CK Mapping
- **Tactic:** {MITRE_TACTIC}
- **Technique(s):** {MITRE_TECHNIQUE_ID} - {MITRE_TECHNIQUE_NAME}

### D3FEND Countermeasures
- **Countermeasure(s):** {D3FEND_COUNTERMEASURES}
- **Target Artifact(s):** {D3FEND_ARTIFACTS}

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment
### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** {ZIG_PILLAR_NAME}
- **Associated Capability:** {ZIG_CAPABILITY_ID} - {ZIG_CAPABILITY_NAME}

---

## 4. Technology Recommendations
- **Recommended Technologies:** {ZIG_TECHNOLOGY_MAPPINGS}
- **Implementation Notes:** {TECHNOLOGY_IMPLEMENTATION_NOTES}

---

## 5. Plan of Action and Milestones (POA&M)
- [ ] **Phase 1 (Immediate):** {IMMEDIATE_ACTION}
- [ ] **Phase 2 (Short-Term):** {SHORT_TERM_ACTION}
- [ ] **Phase 3 (Long-Term/Strategic):** {LONG_TERM_ACTION}
```

---

## Execution Instructions for Claude
1. Create the files exactly as specified.
2. If the user successfully installed `pip install sentence-transformers numpy scikit-learn`, execute `python scripts/embed_graph.py`.
3. If the user *cannot* install ML packages, skip step 2. The `graph_engine.py` will catch the `ImportError` on initialization and automatically route `semantic_search()` queries into the exact `search_nodes()` keyword function.
4. Your job is now complete. The user can import `KnowledgeGraphEngine` to build automated threat-translation agents.

---

## 5. Bonus: Assessment Ingestion Engine
To process massive, multi-tab Excel reports from disparate red/blue teams (which have wildly varying schemas), create `scripts/ingest_assessment.py`. This script extracts all rows across all tabs, stringifies them regardless of column names, and converts the findings into their own vector embeddings so an agent can semantically search the raw data!

```python
import sys
import os
import json
import argparse
import pandas as pd

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False
    print("Warning: Machine Learning libraries (sentence-transformers, numpy) not found. Will only output flattened CSV.")

def ingest_file(filepath):
    print(f"Ingesting {filepath}...")
    
    if filepath.endswith('.xlsx') or filepath.endswith('.xls'):
        sheets = pd.read_excel(filepath, sheet_name=None, header=None)
    elif filepath.endswith('.csv'):
        sheets = {"Sheet1": pd.read_csv(filepath, header=None)}
    else:
        print("Unsupported file format. Please provide a .csv or .xlsx file.")
        sys.exit(1)
        
    all_findings = []
    
    for sheet_name, raw_df in sheets.items():
        max_non_nulls = 0
        header_idx = 0
        
        for idx, row in raw_df.head(50).iterrows():
            non_null_count = row.notna().sum()
            if non_null_count > max_non_nulls:
                max_non_nulls = non_null_count
                header_idx = idx
                
        if max_non_nulls == 0: continue
            
        header_row = raw_df.iloc[header_idx].astype(str)
        header_row = [str(val) if str(val) != 'nan' else f"Unnamed_{i}" for i, val in enumerate(header_row)]
        
        df = raw_df.iloc[header_idx + 1:].copy()
        df.columns = header_row
        df = df.dropna(how='all')
        
        for idx, row in df.iterrows():
            finding_text_parts = []
            row_data = {"_sheet": sheet_name}
            
            for col_name, value in row.items():
                if pd.notna(value) and str(value).strip() != "" and str(value).strip() != "nan":
                    finding_text_parts.append(f"{col_name}: {str(value).strip()}")
                    row_data[str(col_name)] = str(value).strip()
            
            if finding_text_parts:
                full_text = " | ".join(finding_text_parts)
                row_data["_semantic_text"] = full_text
                all_findings.append(row_data)
                
    if not all_findings:
        print("No data found to process.")
        return
        
    flattened_df = pd.DataFrame(all_findings)
    csv_out = flattened_df.drop(columns=['_semantic_text'])
    csv_path = "processed_assessment.csv"
    csv_out.to_csv(csv_path, index=False)
    
    if SEMANTIC_ENABLED:
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts_to_embed = flattened_df['_semantic_text'].tolist()
        embeddings = model.encode(texts_to_embed, show_progress_bar=True)
        np.savez("assessment_embeddings.npz", embeddings=embeddings)
        with open("assessment_metadata.json", 'w', encoding='utf-8') as f:
            json.dump({"findings": texts_to_embed}, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and optionally embed assessment reports (Excel/CSV)")
    parser.add_argument("filepath", help="Path to the .xlsx or .csv file")
    args = parser.parse_args()
    ingest_file(args.filepath)
```

**Execution:** Run `python scripts/ingest_assessment.py <path_to_report.xlsx>` to process a report.

---

## 6. Workflow: From Threat Intel to Remediation Plan (For the End-User & Agent)
Once this repository is reconstructed on the high side, here is how an LLM Agent (like Claude) should be prompted to use it:

**Phase 1: Entity Extraction**
- **Input:** You receive an unstructured blue team assessment (e.g., *"The red team bypassed authentication by forging tickets and moved laterally."*)
- **Agent Action:** Extract the core technical actions or vulnerabilities from the text.

**Phase 2: Graph Mapping (Semantic or Keyword)**
- **Agent Action:** Use the Python `KnowledgeGraphEngine.semantic_search(text)` (or `search_nodes()` if air-gapped) to programmatically map the extracted actions to the closest MITRE ATT&CK node (e.g., `T1558.001 - Golden Ticket`).

**Phase 3: The Mitigation Crawl**
- **Agent Action:** Use `KnowledgeGraphEngine.crawl_subgraph(node="T1558.001", depth=3)`.
- **Result:** The graph returns a JSON object containing connected MITRE D3FEND countermeasures (e.g., *Credential Rotation*, *Access Control*).

**Phase 4: Zero Trust (ZIG) Correlation**
- **Agent Action:** The agent analyzes the D3FEND countermeasures, then queries the ZIG framework via `search_nodes("Credential")`. It locates the relevant ZIG Capability (e.g., *ZIG-CAP-1.5 - Identity Federation*) and crawls it to find the specific Technology implementations (e.g., *Identity Governance and Administration (IGA)*).

**Phase 5: Output Generation**
- **Agent Action:** The agent compiles all the raw data extracted from the graph in Phases 3 and 4, and uses it to fill out the `assessment_template.md`.
- **Output:** A standardized, markdown-formatted Plan of Action and Milestones (POA&M) mapping the threat directly to NSA-approved Zero Trust capabilities and hardware/software classes.
