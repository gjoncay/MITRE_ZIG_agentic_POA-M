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

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** {EXPLOITATION_SCENARIO}
- **Potential Impact:** {BUSINESS_IMPACT}

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique.*
- **Tactic:** {MITRE_TACTIC}
- **Technique(s):** [{MITRE_TECHNIQUE_ID}] {MITRE_TECHNIQUE_NAME}
- **Description:** {MITRE_TECHNIQUE_DESCRIPTION}

### Supplemental MITRE Data (Analytics & Mitigations)
*Associated defensive guidance from the MITRE framework.*
- **Analytics/Detections:** {MITRE_ANALYTICS}
- **Native Mitigations:** {MITRE_MITIGATIONS}

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
            
        # Extract metadata from rows above the header
        metadata_parts = []
        for i in range(header_idx):
            row_vals = raw_df.iloc[i].dropna().astype(str).tolist()
            for val in row_vals:
                if val.strip() and val.strip() != 'nan':
                    metadata_parts.append(val.strip())
        sheet_metadata = " | ".join(metadata_parts)
            
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
                    
            if sheet_metadata:
                row_data["Sheet Context"] = sheet_metadata
                finding_text_parts.insert(0, f"Sheet Context: {sheet_metadata}")
            
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
- **Agent Action:** Use the Python `KnowledgeGraphEngine.semantic_search(text)` (or `search_nodes()` if air-gapped) to programmatically map the extracted actions to the closest MITRE ATT&CK **Technique** node (e.g., `T1558.001 - Golden Ticket`). You must explicitly filter for node IDs that start with 'T' to ensure you are mapping to a Technique, not an Analytic or Mitigation.

**Phase 3: The Mitigation Crawl**
- **Agent Action:** Use `KnowledgeGraphEngine.crawl_subgraph(node="T1558.001", depth=3)`.
- **Result:** The graph returns a JSON object containing connected MITRE D3FEND countermeasures (e.g., *Credential Rotation*, *Access Control*).

**Phase 4: Zero Trust (ZIG) Correlation**
- **Agent Action:** The agent analyzes the D3FEND countermeasures, then queries the ZIG framework via `search_nodes("Credential")`. It locates the relevant ZIG Capability (e.g., *ZIG-CAP-1.5 - Identity Federation*) and crawls it to find the specific Technology implementations (e.g., *Identity Governance and Administration (IGA)*).

**Phase 5: Output Generation**
- **Agent Action:** The agent compiles all the raw data extracted from the graph in Phases 3 and 4, and uses it to fill out the `assessment_template.md`.
- **Output:** A standardized, markdown-formatted Plan of Action and Milestones (POA&M) mapping the threat directly to NSA-approved Zero Trust capabilities and hardware/software classes.

---

## 7. The Automated Batch Processor (Agent Proxy)
Instead of forcing the LLM agent to manually perform the graph traversal steps one by one for every finding, you can use this batch processor. This script acts as an Agent Proxy. It reads the `processed_assessment.csv`, performs all the exact T-code filtering and graph logic we designed, and automatically generates the Markdown reports.

Create `agent_batch_processor.py`:

```python
import sys
import os
import pandas as pd
from datetime import datetime

# Add the scripts directory to path to import graph_engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
from graph_engine import KnowledgeGraphEngine

def generate_reports():
    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()
    
    # Read the flattened mock data
    try:
        df = pd.read_csv("processed_assessment.csv")
    except FileNotFoundError:
        print("Could not find processed_assessment.csv. Did you run ingest_assessment.py?")
        return
        
    # Let's filter for High/Critical severity issues to focus our narrow reports
    target_findings = df[df['Severity'].isin(['High', 'Critical'])].head(3)
    
    # Read the markdown template
    with open("assessment_template.md", "r") as f:
        template = f.read()

    output_dir = "mock_output"
    os.makedirs(output_dir, exist_ok=True)
    
    for index, row in target_findings.iterrows():
        finding_text = row['Finding']
        ip = row['IP']
        hostname = row['Hostname']
        
        print(f"\n[{index}] Processing Threat: {finding_text}")
        
        # 1. Graph Mapping (Semantic Search)
        # Fetch a wider net to find the top Technique (T-code)
        mitre_results = engine.semantic_search(finding_text, top_k=20)
        mitre_node = None
        for res in mitre_results:
            nid = res[0]
            if nid.startswith('T') and nid[1].isdigit():
                mitre_node = res
                break
                
        if not mitre_node:
            print(f"[{index}] No MITRE technique found for '{finding_text}'")
            continue
            
        mitre_node_id, mitre_node_data, score = mitre_node
        mitre_name = mitre_node_data.get('name', 'Unknown')
        
        # 1.5 Extract Tactic
        mitre_tactic = "Unknown Tactic"
        for u, v, data in engine.graph.out_edges(mitre_node_id, data=True):
            if data.get('relationship') == 'belongs_to_tactic':
                mitre_tactic = v
                break
        
        # 2. Mitigation Crawl (D3FEND & Supplementals)
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        d3fend_countermeasures = []
        d3fend_artifacts = []
        analytics = []
        mitigations = []
        
        if mitre_subgraph:
            for nid, ndata in mitre_subgraph['nodes'].items():
                if ndata.get('type') == 'd3fend_countermeasure':
                    d3fend_countermeasures.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ndata.get('type') == 'd3fend_artifact':
                    d3fend_artifacts.append(f"[{nid}] {ndata.get('name', nid)}")
                elif nid.startswith('AN'):
                    analytics.append(f"[{nid}] {ndata.get('name', 'Analytic')}")
                elif nid.startswith('M') and nid[1].isdigit():
                    mitigations.append(f"[{nid}] {ndata.get('name', 'Mitigation')}")
                    
        d3fend_cm_str = "\n  - ".join(d3fend_countermeasures[:3]) if d3fend_countermeasures else "System Hardening"
        if d3fend_countermeasures: d3fend_cm_str = "\n  - " + d3fend_cm_str
        d3fend_art_str = ", ".join(d3fend_artifacts[:3]) if d3fend_artifacts else "System Configuration"
        mitre_analytics_str = "\n  - ".join(analytics[:2]) if analytics else "None specified"
        mitre_mitigations_str = "\n  - ".join(mitigations[:2]) if mitigations else "None specified"
        if analytics: mitre_analytics_str = "\n  - " + mitre_analytics_str
        if mitigations: mitre_mitigations_str = "\n  - " + mitre_mitigations_str
        
        # 3. Zero Trust (ZIG) Correlation
        # We will search ZIG for the first D3FEND countermeasure, or fallback to 'Authentication' / 'Access'
        search_term = d3fend_countermeasures[0] if d3fend_countermeasures else "Access"
        
        zig_results = engine.search_nodes(search_term, exact_match=False)
        zig_caps = [n for n in zig_results if n[1].get('type') == 'zig_capability']
        zig_techs = [n for n in zig_results if n[1].get('type') == 'zig_technology']
        
        zig_cap_id = zig_caps[0][0] if zig_caps else "ZIG-CAP-1.5"
        zig_cap_name = zig_caps[0][1].get('name', 'Identity Federation') if zig_caps else "Identity Federation and User Credentialing"
        zig_pillar = "User Pillar" # Simplified for this demo script
        
        zig_tech_str = ", ".join([f"[{t[0]}] {t[1].get('name')}" for t in zig_techs[:2]]) if zig_techs else "[ZIG-TECH-54] Identity Governance"
        
        # AI generated "So What" logic (mocked up based on finding)
        if "Kerberos" in finding_text or "Delegation" in finding_text:
            exploitation = "An adversary can request authentication tickets offline and crack them, or use unconstrained delegation to impersonate highly privileged users across the domain."
            impact = "Complete domain compromise, unauthorized access to all Active Directory integrated services."
            imm_action = f"Disable unconstrained delegation or enforce Kerberos Pre-Auth on {hostname} ({ip})."
        elif "password" in finding_text.lower():
            exploitation = "Adversaries can easily guess or brute-force administrative credentials to gain elevated privileges."
            impact = "Local system takeover leading to lateral movement across the network."
            imm_action = f"Immediately rotate the local administrator password on {hostname} ({ip}) and deploy LAPS."
        else:
            exploitation = "Adversaries could exploit this misconfiguration to execute unauthorized code or access sensitive data."
            impact = "Data breach or loss of system availability."
            imm_action = f"Investigate and patch/reconfigure {hostname} ({ip})."
            
        # 4. Generate Output Markdown
        report_content = template.format(
            DATE=datetime.now().strftime('%Y-%m-%d'),
            ASSESSMENT_ID=f"ASMT-{index+1000}",
            THREAT_INPUT_SUMMARY=f"[{ip}] [{hostname}] {finding_text}",
            EXPLOITATION_SCENARIO=exploitation,
            BUSINESS_IMPACT=impact,
            MITRE_TACTIC=mitre_tactic,
            MITRE_TECHNIQUE_ID=mitre_node_id,
            MITRE_TECHNIQUE_NAME=mitre_name,
            MITRE_TECHNIQUE_DESCRIPTION=mitre_node_data.get('description', 'Unknown').split('.')[0] + ".",
            MITRE_ANALYTICS=mitre_analytics_str,
            MITRE_MITIGATIONS=mitre_mitigations_str,
            D3FEND_COUNTERMEASURE_1=d3fend_countermeasures[0] if len(d3fend_countermeasures) > 0 else "[D3-SH] System Hardening",
            D3FEND_COUNTERMEASURE_2=d3fend_countermeasures[1] if len(d3fend_countermeasures) > 1 else "[D3-CM] Continuous Monitoring",
            D3FEND_ARTIFACTS=d3fend_art_str,
            ZIG_PILLAR_NAME=zig_pillar,
            ZIG_CAPABILITY_ID=zig_cap_id,
            ZIG_CAPABILITY_NAME=zig_cap_name,
            ZIG_ACTIVITY_1="Identify and remediate vulnerable configurations",
            ZIG_TECHNOLOGY_1=zig_techs[0][1].get('name') if len(zig_techs) > 0 else "Identity Governance",
            ZIG_TECHNOLOGY_2=zig_techs[1][1].get('name') if len(zig_techs) > 1 else "Configuration Management Database (CMDB)",
            TECHNOLOGY_IMPLEMENTATION_NOTES="Ensure configurations align with vendor security baselines.",
            IMMEDIATE_ACTION=imm_action,
            SHORT_TERM_ACTION="Implement continuous monitoring for this vulnerability class.",
            LONG_TERM_ACTION=f"Integrate {zig_cap_name} architecture fully."
        )
        
        out_path = os.path.join(output_dir, f"ASMT-{index+1000}.md")
        with open(out_path, "w") as f:
            f.write(report_content)
            
        print(f"Generated {out_path} -> Mapped to {mitre_node_id} & {zig_cap_id}")

if __name__ == "__main__":
    generate_reports()

```


**Execution:** Run `python agent_batch_processor.py` (ensure you ran `python scripts/ingest_assessment.py <data>` first!).

---

## 8. Guidance for External Embedding APIs (Agency API)

If you cannot host the `sentence-transformers` model locally on the high-side network and instead need to point to a secure internal Agency API (e.g., an internal OpenAI/Claude embedding endpoint), you will need to adjust the code in two specific places.

### Scaffold 1: Generating the Vectors (`scripts/embed_graph.py`)
When you initialize the graph for the first time, you need to embed all MITRE/ZIG nodes. Replace the local `model.encode()` call with a loop that calls your API:

```python
# In scripts/embed_graph.py (replace model.encode)
api_embeddings = []
for text in texts_to_embed:
    # Example pseudo-code for your internal API
    # response = requests.post("https://internal.api.mil/v1/embeddings", json={"input": text})
    # vector = response.json()['data'][0]['embedding']
    # api_embeddings.append(vector)
    pass
    
embeddings = np.array(api_embeddings)
np.savez("graph_embeddings.npz", embeddings=embeddings)
```

### Scaffold 2: Querying the Vectors (`scripts/graph_engine.py`)
During live agent operations, the agent will pass the threat finding text to `semantic_search()`. You must replace the local model inference with an API call.

```python
# In scripts/graph_engine.py (inside semantic_search)
def semantic_search(self, query_text, top_k=3):
    # Call your API instead of self.embedding_model.encode()
    # vector = requests.post("https://internal.api.mil/v1/embeddings", json={"input": query_text}).json()['data'][0]['embedding']
    
    # CRITICAL: Sklearn's cosine_similarity expects a 2D numpy array. 
    # Wrap your API vector in a list before converting to numpy array:
    query_vec = np.array([vector]) 
    
    similarities = cosine_similarity(query_vec, self.embeddings)[0]
    # ... rest of function remains identical
```

By making these two small adjustments, the exact same vector math and cosine similarity ranking will execute perfectly, but the heavy lifting of the NLP model will be offloaded to your secure Agency API!
