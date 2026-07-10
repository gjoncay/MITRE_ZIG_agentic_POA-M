# PORTABLE RECONSTRUCTION BUNDLE — MITRE/ZIG Threat Assessment System

> **PROMPT — for the autonomous coding agent on the high-side network:**
> This single document contains the COMPLETE source code (13 files) of a
> Python threat-intelligence system, because the cross-domain transfer only
> permits text documents. Your job is to materialize the files, verify them
> against the checksums baked into this document, and stand the system up.
>
> **Rules:**
> 1. Do NOT retype or "reconstruct" the code from understanding — extract it
>    mechanically using STEP 0 below, so the checksums prove byte-exactness.
> 2. Do not modify, reformat, or "improve" any file.
> 3. Follow the sections in order and run every verification command.
> 4. The four data CSVs (`mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`,
>    `zig_edges.csv`) are plain text and should have been transferred alongside
>    this document. If they are missing, see Section 5.

---

# STEP 0 — Extract the files

Create ONE file by hand, `extract_bundle.py`, with exactly this content
(it is short deliberately — everything else extracts mechanically):

`````python
"""Extracts every embedded file from PORTABLE_RECONSTRUCTION_BUNDLE.md.

Usage:  python3 extract_bundle.py [bundle.md]

Looks for blocks of the form:
    ## FILE: `relative/path` (sha256=<64 hex chars>)
    ````lang
    ...content...
    ````
Writes each file to its relative path and verifies its SHA-256 checksum.
Exits non-zero if any checksum fails. Pure stdlib; needs only Python 3.
"""
import sys
import os
import re
import hashlib

HEADER = re.compile(r"^## FILE: `([^`]+)` \(sha256=([0-9a-f]{64})\)\s*$")
FENCE = re.compile(r"^(`{4,})")

def main(bundle_path):
    pending = None   # (path, sha) seen, waiting for its opening fence
    fence = None     # exact backtick run that will close the current block
    path = sha = None
    buf = []
    written = failed = 0

    with open(bundle_path, encoding="utf-8") as f:
        for line in f:
            if fence is None:
                m = HEADER.match(line)
                if m:
                    pending = (m.group(1), m.group(2))
                    continue
                fm = FENCE.match(line)
                if pending and fm:
                    fence = fm.group(1)
                    path, sha = pending
                    pending = None
                    buf = []
            else:
                if line.rstrip("\n") == fence:
                    content = "".join(buf)
                    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    if os.path.dirname(path):
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="") as out:
                        out.write(content)
                    ok = actual == sha
                    print(("OK   " if ok else "FAIL ") + path)
                    written += 1
                    failed += (not ok)
                    fence = None
                else:
                    buf.append(line)

    print(f"\n{written} files written, {failed} checksum failures")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "PORTABLE_RECONSTRUCTION_BUNDLE.md")
`````

Then, in an empty project directory containing this document:

```bash
python3 extract_bundle.py PORTABLE_RECONSTRUCTION_BUNDLE.md
```

Expected output: one `OK   <path>` line per file below, ending in
`13 files written, 0 checksum failures`. **If any line says FAIL, the
document was corrupted or altered in transfer (smart quotes, stripped
whitespace, line-ending conversion are the usual suspects) — do not proceed;
fix the transfer or fall back to careful manual copy of that one file, then
re-run the extractor to re-verify.**

## Extraction manifest

| File | Bytes | SHA-256 (first 16) |
|---|---|---|
| `requirements.txt` | 901 | `40f2e41c36e7547e...` |
| `scripts/graph_engine.py` | 8763 | `ea028c5329106e18...` |
| `scripts/embed_graph.py` | 2187 | `87790cb1eb5f97b1...` |
| `scripts/ingest_assessment.py` | 5225 | `72854a498dee2023...` |
| `agent_batch_processor.py` | 9859 | `3fe533d05c92213d...` |
| `agent_crawl_example.py` | 5483 | `0a80085fb98f96f2...` |
| `assessment_template.md` | 2249 | `a230eb14a328f7fc...` |
| `threat_assessment_skill.md` | 4651 | `49a307e936385d51...` |
| `consolidate_mitre_data.py` | 8879 | `134f68671af08c16...` |
| `scripts/parse_zig_data.py` | 5861 | `5e16d679ada7cd25...` |
| `import_to_neo4j.py` | 2920 | `c96e1eda600630e4...` |
| `build_deployment_guide.py` | 18685 | `0c085f6624ab1f50...` |
| `README.md` | 3512 | `7d982161c2af579d...` |

---

# STEP 1 — Assemble the data

Place the four CSVs (ported separately, as text) in the project root next to
`extract_bundle.py`. Expected layout after extraction + data placement:

```text
./
├── mitre_nodes.csv        ├── agent_batch_processor.py
├── mitre_edges.csv        ├── agent_crawl_example.py
├── zig_nodes.csv          ├── assessment_template.md
├── zig_edges.csv          ├── threat_assessment_skill.md
├── requirements.txt       ├── consolidate_mitre_data.py
├── README.md              ├── import_to_neo4j.py
├── build_deployment_guide.py
└── scripts/
    ├── graph_engine.py
    ├── embed_graph.py
    ├── ingest_assessment.py
    └── parse_zig_data.py
```

Install dependencies — Tier 1 is the only hard requirement (see the tier
comments inside `requirements.txt`):

```bash
pip install networkx pandas
```

**If `numpy`, `scikit-learn`, and `sentence-transformers` cannot be installed
here, that is fine and expected**: the engine detects the missing libraries and
routes `semantic_search()` through a ranked keyword search automatically. Do
not treat the `[Warning] Semantic search unavailable...` message as an error.

---

# STEP 2 — Verify

```bash
python3 scripts/graph_engine.py
```

Must print `Knowledge Graph initialized with ~5150 nodes and ~29208 edges`
(small drift is fine if the CSVs were regenerated from newer MITRE data; a
number near 0 means the CSVs are not in the project root), then successful
lookups of `ZIG-PIL-1` and `T1548`, then search results for a test query.

Then the 3-tuple contract:

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
r = e.semantic_search('attacker dumped password hashes from memory', top_k=5)
assert r and len(r[0]) == 3
for nid, data, score in r: print(nid, data.get('name'), round(score, 3))
"
```

Expected: five rows with credential-dumping techniques near the top (e.g.
`T1003.001 OS Credential Dumping: LSASS Memory`).

End-to-end smoke test:

```bash
python3 - <<'EOF'
import pandas as pd
pd.DataFrame({
    "IP": ["192.168.1.15"], "Hostname": ["DC-01"],
    "Finding": ["Kerberos Pre-Authentication disabled on service accounts"],
    "Severity": ["High"],
}).to_csv("smoke_test.csv", index=False)
EOF
python3 scripts/ingest_assessment.py smoke_test.csv
python3 agent_batch_processor.py --limit 1
```

Expected: `Generated .../mock_output/ASMT-1000.md -> Mapped to T... & ZIG-CAP-...`,
and the generated report has every section filled with IDs that exist in the
graph (spot-check any of them with `engine.query_node('<id>')`).

---

# STEP 3 — OPTIONAL semantic mode

Only if Tier 3 libraries installed AND the `all-MiniLM-L6-v2` model files were
ported (HuggingFace cache directory
`models--sentence-transformers--all-MiniLM-L6-v2`, ~90 MB — a separate binary
transfer; without it, stay in keyword mode). Place the cache under
`~/.cache/huggingface/hub/`, then:

```bash
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
python3 scripts/embed_graph.py     # one-time; rerun whenever the CSVs change
python3 scripts/graph_engine.py    # should now search WITHOUT the fallback warning
```

If pointing at an internal embeddings API instead, the two call sites to
replace are marked with `EXTERNAL API SCAFFOLDING` comments in
`scripts/embed_graph.py` and `scripts/graph_engine.py`.

---

# STEP 4 — Operate

Read `threat_assessment_skill.md` (extracted above) — it is the operating
prompt for the analysis agent: per finding, map to an ATT&CK T-code via
`semantic_search` (filter IDs starting with `T` + digit), crawl defenses with
`crawl_subgraph(t_code, depth=2)` (collect `d3fend_technique`,
`defensive_artifact`, `attack_analytic`, `attack_mitigation` node types),
correlate to Zero Trust with `keyword_rank(countermeasure_name)` (filter
`zig_capability` / `zig_technology`), and fill `assessment_template.md` —
never inventing framework IDs. Bulk mode:
`python3 scripts/ingest_assessment.py <report.xlsx>` then
`python3 agent_batch_processor.py --limit N`.

For the full reference documentation (asset tiers, graph schema tables,
troubleshooting), regenerate it locally:

```bash
python3 build_deployment_guide.py   # writes Air_Gapped_Deployment_Guide.md
```

---

# STEP 5 — ONLY if the CSVs did not survive transfer

The graph can be regenerated from raw MITRE/NSA sources IF they can be
obtained on this network (they are common on classified mirrors):
`enterprise-attack-v19.1(1).xlsx` (or newer), `d3fend.csv`,
`d3fend-full-mappings.csv`, `ATT&CK_D3FEND_Mappings.ods`, and text extracts of
the NSA ZIG PDFs plus `zig_tech_mappings.txt`. Then (Tier 2 libs required:
`pip install openpyxl odfpy`):

```bash
python3 consolidate_mitre_data.py    # -> mitre_nodes.csv, mitre_edges.csv
python3 scripts/parse_zig_data.py    # -> zig_nodes.csv, zig_edges.csv (run where the ZIG .txt files are)
```

A few dropped edges reported by the integrity pass is normal (tens, not
hundreds). After regenerating, redo STEP 2, and STEP 3 if in semantic mode.

---

# EMBEDDED FILES

## FILE: `requirements.txt` (sha256=40f2e41c36e7547ea0f3a4614cf04eb65259c77336468fbe0d40b9001d0fa503)

````text
# TIER 1 — REQUIRED. The graph engine will not run without these.
networkx>=3.0
pandas>=2.0

# TIER 2 — REQUIRED only to regenerate datasets from the raw source files
# (consolidate_mitre_data.py, ingest_assessment.py reading Excel/ODS).
openpyxl>=3.1        # .xlsx reading
odfpy>=1.4           # .ods reading (ATT&CK_D3FEND_Mappings.ods)

# TIER 3 — OPTIONAL. Enables semantic (vector) search. If these cannot be
# installed on the air-gapped network, the engine automatically falls back
# to ranked keyword search — do NOT treat their absence as a failure.
numpy>=1.24
scikit-learn>=1.3
sentence-transformers>=2.2   # pulls in torch (~2GB+); also requires the
                             # all-MiniLM-L6-v2 model files to be ported
                             # (see Air_Gapped_Deployment_Guide.md)

# TIER 4 — OPTIONAL, only for the Neo4j export path (import_to_neo4j.py)
# neo4j>=5.0
````

---

## FILE: `scripts/graph_engine.py` (sha256=ea028c5329106e189a6a721051541898db6cd8b8596f7d76b23558fa60d275da)

````python
import csv
import json
import os
import re
import networkx as nx

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False

# All data files live in the repository root (the parent of this scripts/ dir),
# so the engine works no matter what directory it is launched from.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Words too generic to score on during keyword-fallback search
STOPWORDS = {
    'the', 'a', 'an', 'and', 'or', 'of', 'on', 'in', 'to', 'for', 'with',
    'by', 'is', 'are', 'was', 'were', 'be', 'been', 'this', 'that', 'it',
    'as', 'at', 'from', 'has', 'have', 'had', 'via', 'using', 'used', 'use'
}

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
            npz_path = os.path.join(BASE_DIR, 'graph_embeddings.npz')
            meta_path = os.path.join(BASE_DIR, 'embedding_metadata.json')

            if os.path.exists(npz_path) and os.path.exists(meta_path):
                self.embeddings = np.load(npz_path)['embeddings']
                with open(meta_path, 'r', encoding='utf-8') as f:
                    self.embedding_node_ids = json.load(f)['node_ids']
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                print("[Info] Embedding files not found. Semantic search disabled; keyword fallback active.")
                self.semantic_enabled = False
        except Exception as e:
            print(f"Failed to load semantic model/embeddings: {e}")
            self.semantic_enabled = False

    def load_data(self):
        for nodes_file, edges_file in [('mitre_nodes.csv', 'mitre_edges.csv'),
                                       ('zig_nodes.csv', 'zig_edges.csv')]:
            try:
                with open(os.path.join(BASE_DIR, nodes_file), 'r', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        self.graph.add_node(row['id'], **row)
                with open(os.path.join(BASE_DIR, edges_file), 'r', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])
            except Exception as e:
                print(f"Error loading {nodes_file}/{edges_file}: {e}")

        print(f"Knowledge Graph initialized with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")

    def query_node(self, node_id):
        """Returns the attributes of a specific node."""
        if self.graph.has_node(node_id):
            return self.graph.nodes[node_id]
        return None

    def search_nodes(self, keyword, exact_match=False):
        """Searches node IDs, Names, or Descriptions for a keyword (substring match)."""
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

    def keyword_rank(self, query_text, top_k=3):
        """Ranks nodes by how many words of the query appear in their name/description.

        This is the air-gapped fallback for semantic_search(): unlike search_nodes(),
        it does not require the entire query to appear as one substring, so full
        sentences of threat intel still return useful matches.
        Returns [(node_id, node_data, score)] with score in 0..1.
        """
        tokens = [t for t in re.findall(r'[a-z0-9\-]+', query_text.lower())
                  if len(t) > 2 and t not in STOPWORDS]
        if not tokens:
            return []

        scored = []
        for n, data in self.graph.nodes(data=True):
            name = str(data.get('name', '')).lower()
            desc = str(data.get('description', '')).lower()
            score = 0.0
            for t in tokens:
                if t in name:
                    score += 2.0  # name hits are far stronger signals
                elif t in desc:
                    score += 1.0
            if score > 0:
                scored.append((n, data, score / (2.0 * len(tokens))))

        scored.sort(key=lambda x: x[2], reverse=True)
        return scored[:top_k]

    def semantic_search(self, query_text, top_k=3):
        """Performs a semantic vector search if enabled, else falls back to ranked keyword search.

        Always returns a list of (node_id, node_data, score) 3-tuples in both modes.
        """
        if not self.semantic_enabled or self.embeddings is None:
            print("[Warning] Semantic search unavailable. Falling back to ranked keyword search.")
            return self.keyword_rank(query_text, top_k=top_k)

        # --- EXTERNAL API SCAFFOLDING ---
        # If using an Agency API instead of a local model:
        # query_vec = get_api_embedding(query_text) # Must return a 2D array e.g. np.array([[0.1, 0.2, ...]])
        # --------------------------------

        query_vec = self.embedding_model.encode([query_text])
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

    print("\nTest: Search (semantic if available, keyword fallback otherwise)")
    for nid, data, score in engine.semantic_search("attacker dumped password hashes from memory", top_k=3):
        print(f"  [{nid}] {data.get('name', '')} (score: {score:.3f})")
````

---

## FILE: `scripts/embed_graph.py` (sha256=87790cb1eb5f97b1f12ad617b37ea811ba7e005711f1ef5c096b87e575ee1559)

````python
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
````

---

## FILE: `scripts/ingest_assessment.py` (sha256=72854a498dee2023b754b82709e81da6ff88a05bbb9af31fa8b9ed4a625eb2a2)

````python
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
    
    # Check if excel or csv
    if filepath.endswith('.xlsx') or filepath.endswith('.xls'):
        # Read without headers initially to deal with admin metadata/spanned cells
        sheets = pd.read_excel(filepath, sheet_name=None, header=None)
    elif filepath.endswith('.csv'):
        sheets = {"Sheet1": pd.read_csv(filepath, header=None)}
    else:
        print("Unsupported file format. Please provide a .csv or .xlsx file.")
        sys.exit(1)
        
    all_findings = []
    
    # Process each sheet
    for sheet_name, raw_df in sheets.items():
        print(f"Processing sheet: {sheet_name} ({len(raw_df)} raw rows)")
        
        # Heuristic: The real header row is usually the one in the top 50 rows 
        # with the most non-null columns (ignoring the admin metadata on top)
        max_non_nulls = 0
        header_idx = 0
        
        for idx, row in raw_df.head(50).iterrows():
            # Count cells that aren't empty/NaN
            non_null_count = row.notna().sum()
            if non_null_count > max_non_nulls:
                max_non_nulls = non_null_count
                header_idx = idx
                
        if max_non_nulls == 0:
            print(f"  Skipping {sheet_name}: Appears empty.")
            continue
            
        print(f"  Found logical header at row {header_idx + 1}. Extracting admin metadata above it...")
        
        # Extract all text from rows above the header to preserve context
        metadata_parts = []
        for i in range(header_idx):
            row_vals = raw_df.iloc[i].dropna().astype(str).tolist()
            for val in row_vals:
                if val.strip() and val.strip() != 'nan':
                    metadata_parts.append(val.strip())
        sheet_metadata = " | ".join(metadata_parts)
        
        # Extract the real header and slice the dataframe
        header_row = raw_df.iloc[header_idx].astype(str)
        # Handle empty column names
        header_row = [str(val) if str(val) != 'nan' else f"Unnamed_{i}" for i, val in enumerate(header_row)]
        
        df = raw_df.iloc[header_idx + 1:].copy()
        df.columns = header_row
        
        df = df.dropna(how='all')
        
        # Iterate over rows
        for idx, row in df.iterrows():
            finding_text_parts = []
            row_data = {"_sheet": sheet_name}
            
            # Stringify row based on whatever random schema columns exist
            for col_name, value in row.items():
                if pd.notna(value) and str(value).strip() != "" and str(value).strip() != "nan":
                    finding_text_parts.append(f"{col_name}: {str(value).strip()}")
                    row_data[str(col_name)] = str(value).strip()
            
            if sheet_metadata:
                row_data["Sheet Context"] = sheet_metadata
                # Prepend the sheet context to the semantic text
                finding_text_parts.insert(0, f"Sheet Context: {sheet_metadata}")
            
            if finding_text_parts:
                full_text = " | ".join(finding_text_parts)
                row_data["_semantic_text"] = full_text
                all_findings.append(row_data)
                
    # Save flattened CSV
    if not all_findings:
        print("No data found to process.")
        return
        
    flattened_df = pd.DataFrame(all_findings)
    # Reorder so _semantic_text is first for easy reading, drop it from final CSV
    csv_out = flattened_df.drop(columns=['_semantic_text'])
    csv_path = "processed_assessment.csv"
    csv_out.to_csv(csv_path, index=False)
    print(f"\nSaved flattened raw data to {csv_path} ({len(flattened_df)} total rows).")
    
    # Generate Embeddings
    if SEMANTIC_ENABLED:
        print("\nGenerating semantic embeddings for the assessment findings...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts_to_embed = flattened_df['_semantic_text'].tolist()
        
        embeddings = model.encode(texts_to_embed, show_progress_bar=True)
        
        npz_path = "assessment_embeddings.npz"
        np.savez(npz_path, embeddings=embeddings)
        
        # Save metadata mapping index to the text
        meta_path = "assessment_metadata.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump({"findings": texts_to_embed}, f)
            
        print(f"Successfully saved {len(embeddings)} embeddings to {npz_path}")
        print(f"Agents can now semantically search this raw dataset!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and optionally embed assessment reports (Excel/CSV)")
    parser.add_argument("filepath", help="Path to the .xlsx or .csv file")
    args = parser.parse_args()
    
    ingest_file(args.filepath)
````

---

## FILE: `agent_batch_processor.py` (sha256=3fe533d05c92213d6831cea079a28467addaaec404346beb9fde4b5af51894dc)

````python
import sys
import os
import argparse
import pandas as pd
from datetime import datetime

# Add the scripts directory to path to import graph_engine
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))
from graph_engine import KnowledgeGraphEngine

def first_present(row, candidates, default="Unknown"):
    """Returns the first non-empty value among candidate column names (schemas vary per team)."""
    for col in candidates:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return default

def generate_reports(input_csv, limit):
    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()

    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"Could not find {input_csv}. Did you run scripts/ingest_assessment.py first?")
        return

    # Focus on High/Critical severity issues when a Severity column exists;
    # otherwise process everything up to the limit.
    if 'Severity' in df.columns:
        target_findings = df[df['Severity'].isin(['High', 'Critical'])].head(limit)
    else:
        print("No 'Severity' column found; processing the first rows as-is.")
        target_findings = df.head(limit)

    with open(os.path.join(BASE_DIR, "assessment_template.md"), "r") as f:
        template = f.read()

    output_dir = os.path.join(BASE_DIR, "mock_output")
    os.makedirs(output_dir, exist_ok=True)

    for index, row in target_findings.iterrows():
        finding_text = first_present(row, ['Finding', 'Observation', 'Vulnerability', 'Description'])
        ip = first_present(row, ['IP', 'Target Address', 'Address'], default="N/A")
        hostname = first_present(row, ['Hostname', 'Host', 'Target'], default="N/A")

        print(f"\n[{index}] Processing Threat: {finding_text}")

        # 1. Graph Mapping (Semantic Search)
        # Fetch a wider net so we can filter down to the top Technique (T-code)
        mitre_results = engine.semantic_search(finding_text, top_k=20)
        mitre_node = None
        for nid, ndata, score in mitre_results:
            if nid.startswith('T') and len(nid) > 1 and nid[1].isdigit():
                mitre_node = (nid, ndata, score)
                break

        if not mitre_node:
            print(f"[{index}] No MITRE technique found for '{finding_text}'")
            continue

        mitre_node_id, mitre_node_data, score = mitre_node
        mitre_name = mitre_node_data.get('name', 'Unknown')

        # 1.5 Extract Tactic (belongs_to_tactic points at a TA-node; resolve its name)
        mitre_tactic = "Unknown Tactic"
        for u, v, data in engine.graph.out_edges(mitre_node_id, data=True):
            if data.get('relationship') == 'belongs_to_tactic':
                tactic_node = engine.query_node(v)
                mitre_tactic = f"[{v}] {tactic_node.get('name', v)}" if tactic_node else v
                break

        # 2. Mitigation Crawl (D3FEND & Supplementals)
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        d3fend_countermeasures = []
        d3fend_artifacts = []
        analytics = []
        mitigations = []

        if mitre_subgraph and 'nodes' in mitre_subgraph:
            for nid, ndata in mitre_subgraph['nodes'].items():
                ntype = ndata.get('type')
                if ntype == 'd3fend_technique':
                    d3fend_countermeasures.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ntype in ('defensive_artifact', 'attack_datacomponent'):
                    d3fend_artifacts.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ntype == 'attack_analytic':
                    analytics.append(f"[{nid}] {ndata.get('description', ndata.get('name', 'Analytic'))[:120]}")
                elif ntype == 'attack_mitigation':
                    mitigations.append(f"[{nid}] {ndata.get('name', 'Mitigation')}")

        d3fend_cm_1 = d3fend_countermeasures[0] if len(d3fend_countermeasures) > 0 else "None found in graph"
        d3fend_cm_2 = d3fend_countermeasures[1] if len(d3fend_countermeasures) > 1 else "None found in graph"
        d3fend_art_str = ", ".join(d3fend_artifacts[:3]) if d3fend_artifacts else "None found in graph"
        mitre_analytics_str = ("\n  - " + "\n  - ".join(analytics[:2])) if analytics else "None specified"
        mitre_mitigations_str = ("\n  - " + "\n  - ".join(mitigations[:2])) if mitigations else "None specified"

        # 3. Zero Trust (ZIG) Correlation
        # Rank ZIG nodes against the top countermeasure NAME (not its "[ID] Name" string)
        if d3fend_countermeasures:
            search_term = d3fend_countermeasures[0].split('] ', 1)[-1]
        else:
            search_term = "Access Control"

        zig_ranked = engine.keyword_rank(search_term, top_k=100)
        zig_caps = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_capability']
        zig_techs = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_technology']

        # Fall back to a generic security term if the countermeasure name found nothing
        if not zig_caps:
            fallback_ranked = engine.keyword_rank("access management authentication", top_k=100)
            zig_caps = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_capability']
            if not zig_techs:
                zig_techs = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_technology']

        zig_cap_id = zig_caps[0][0] if zig_caps else "None found"
        zig_cap_name = zig_caps[0][1].get('name', 'Unknown') if zig_caps else "No matching ZIG capability"

        # Resolve the capability's pillar from the graph instead of hardcoding it
        zig_pillar = "Unknown Pillar"
        if zig_caps:
            for u, v, data in engine.graph.out_edges(zig_cap_id, data=True):
                if data.get('relationship') == 'belongs_to_pillar':
                    pillar_node = engine.query_node(v)
                    zig_pillar = pillar_node.get('name', v) if pillar_node else v
                    break

        # AI generated "So What" logic (mocked up based on finding keywords).
        # NOTE: when an LLM agent drives this pipeline, the agent should write
        # these three fields itself from the finding context.
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
            D3FEND_COUNTERMEASURE_1=d3fend_cm_1,
            D3FEND_COUNTERMEASURE_2=d3fend_cm_2,
            D3FEND_ARTIFACTS=d3fend_art_str,
            ZIG_PILLAR_NAME=zig_pillar,
            ZIG_CAPABILITY_ID=zig_cap_id,
            ZIG_CAPABILITY_NAME=zig_cap_name,
            ZIG_ACTIVITY_1="Identify and remediate vulnerable configurations",
            ZIG_TECHNOLOGY_1=f"[{zig_techs[0][0]}] {zig_techs[0][1].get('name')}" if len(zig_techs) > 0 else "None found in graph",
            ZIG_TECHNOLOGY_2=f"[{zig_techs[1][0]}] {zig_techs[1][1].get('name')}" if len(zig_techs) > 1 else "None found in graph",
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
    parser = argparse.ArgumentParser(description="Batch-generate assessment reports from a processed findings CSV")
    parser.add_argument("--input", default="processed_assessment.csv", help="Flattened findings CSV from ingest_assessment.py")
    parser.add_argument("--limit", type=int, default=3, help="Maximum number of findings to process")
    args = parser.parse_args()
    generate_reports(args.input, args.limit)
````

---

## FILE: `agent_crawl_example.py` (sha256=0a80085fb98f96f21efad2fd0c7b96517673316e2448062212a8e0c9774e6734)

````python
import sys
import os

# Add the scripts directory to path to import graph_engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
from graph_engine import KnowledgeGraphEngine

def format_subgraph(subgraph_data):
    """Utility to print a subgraph nicely."""
    out = f"--- Crawled Depth {subgraph_data['depth_crawled']} from {subgraph_data['start_node']} ---\n"
    out += "Nodes Found:\n"
    for nid, ndata in subgraph_data['nodes'].items():
        out += f"  - [{nid}] {ndata.get('name', '')} ({ndata.get('type', '')})\n"
    out += "Edges:\n"
    for edge in subgraph_data['edges']:
        out += f"  - {edge['source']} --({edge['relationship']})--> {edge['target']}\n"
    return out

if __name__ == "__main__":
    engine = KnowledgeGraphEngine()
    
    print("\n" + "="*50)
    print("MOCK AGENT CRAWL: THREAT INTELLIGENCE ANALYSIS")
    print("="*50)
    
    threat_intel = "Red team executed a Golden Ticket attack (T1558.001) to persist on the domain."
    print(f"\n[Agent Input] {threat_intel}")
    
    print("\n[Agent] Searching MITRE framework using natural language: 'Red team executed a Golden Ticket attack'...")
    mitre_results = engine.semantic_search("Red team executed a Golden Ticket attack", top_k=1)
    if mitre_results:
        # semantic_search always returns (node_id, node_data, score) 3-tuples,
        # in both semantic and keyword-fallback modes
        mitre_node_id, mitre_node_data, score = mitre_results[0]
        print(f"[Agent] Found closest MITRE Node: {mitre_node_data['name']} (Score: {score:.2f})")
        
        print(f"\n[Agent] Crawling MITRE countermeasures for {mitre_node_id} (Depth=2)...")
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        print(format_subgraph(mitre_subgraph))
    
    print("\n[Agent] Based on the MITRE countermeasures (e.g. Identity Management), searching ZIG framework for related Zero Trust concepts...")
    # The agent determines "Identity" and "Access" are key. It searches ZIG nodes for "Authentication" or "Identity"
    zig_results = engine.search_nodes("Identity", exact_match=False)
    zig_candidates = [n for n in zig_results if n[1].get('type') == 'zig_capability']
    
    if zig_candidates:
        # Just pick the first matching capability for the example
        zig_node_id, zig_node_data = zig_candidates[0]
        print(f"[Agent] Found relevant ZIG Node: {zig_node_data['name']} ({zig_node_id})")
        
        print(f"\n[Agent] Crawling ZIG architecture for {zig_node_id} (Depth=2)...")
        zig_subgraph = engine.crawl_subgraph(zig_node_id, depth=2)
        print(format_subgraph(zig_subgraph))
        
    print("\n" + "="*50)
    print("FINAL ASSESSMENT OUTPUT (MARKDOWN TEMPLATE FORMAT)")
    print("="*50 + "\n")
    
    assessment_md = f"""# Threat & Mitigation Assessment Report

**Date:** 2026-07-09
**Assessment ID:** ASMT-90210

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations.*

**Finding / Threat Input:** {threat_intel}

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** An adversary could use a stolen or forged Ticket Granting Ticket (TGT) to impersonate any user on the domain indefinitely, bypassing normal authentication mechanisms and password resets.
- **Potential Impact:** Complete domain compromise, allowing unhindered lateral movement, data exfiltration, and ransomware deployment.

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique.*
- **Tactic:** Credential Access (Inferred)
- **Technique(s):** [T1550.003] Use Alternate Authentication Material: Pass the Ticket
- **Description:** Adversaries may forge Kerberos tickets to bypass authentication.

### Supplemental MITRE Data (Analytics & Mitigations)
*Associated defensive guidance from the MITRE framework.*
- **Analytics/Detections:** 
  - [AN0316] Detects AS-REP roasting attempts by monitoring for Kerberos AS-REQ/AS-REP
- **Native Mitigations:** 
  - [M1038] Execution Prevention

### D3FEND Countermeasures
- **Countermeasure(s):** 
  - Credential Rotation
  - Access Control
- **Target Artifact(s):** Active Directory Ticket Granting Ticket (TGT)

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment

### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** ZIG-PIL-1 - User Pillar
- **Associated Capability:** {zig_node_id} - {zig_node_data['name']}
- **Relevant Activities:** 
  - ZIG-ACT-1.5.1 - Organizational Identity Lifecycle Management (ILM)

---

## 4. Technology Recommendations

- **Recommended Technologies:**
  - ZIG-TECH-54 - Identity Governance and Administration (IGA)
  - ZIG-TECH-101 - Single Sign-On (SSO) and Federation
- **Implementation Notes:** Ensure IdP is configured to enforce MFA and rotate credentials automatically on a fixed cadence.

---

## 5. Plan of Action and Milestones (POA&M)

- [ ] **Phase 1 (Immediate):** Identify and rotate all potentially compromised service account passwords (krbtgt).
- [ ] **Phase 2 (Short-Term):** Deploy robust Identity Governance and Administration (IGA) tools for continuous monitoring.
- [ ] **Phase 3 (Long-Term/Strategic):** Fully integrate Identity Federation across all enclaves per ZIG Capability 1.5.
"""
    print(assessment_md)
````

---

## FILE: `assessment_template.md` (sha256=a230eb14a328f7fc6717782a2300a9bd1b2bc546b082c5dff1439cdc2c430346)

````markdown
# Threat & Mitigation Assessment Report

**Date:** {DATE}
**Assessment ID:** {ASSESSMENT_ID}

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations.*

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
*The defensive mechanisms and artifacts required to detect, isolate, or mitigate the threat based on the D3FEND matrix.*
- **Countermeasure(s):** 
  - {D3FEND_COUNTERMEASURE_1}
  - {D3FEND_COUNTERMEASURE_2}
- **Target Artifact(s):** {D3FEND_ARTIFACTS}

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment

*Mapping the required defensive measures to the principles of Zero Trust.*

### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** {ZIG_PILLAR_NAME}
- **Associated Capability:** {ZIG_CAPABILITY_ID} - {ZIG_CAPABILITY_NAME}
- **Relevant Activities:** 
  - {ZIG_ACTIVITY_1}

---

## 4. Technology Recommendations

*Specific hardware, software, or configuration classes required to implement the ZIG capabilities and D3FEND countermeasures.*

- **Recommended Technologies:**
  - {ZIG_TECHNOLOGY_1}
  - {ZIG_TECHNOLOGY_2}
- **Implementation Notes:** {TECHNOLOGY_IMPLEMENTATION_NOTES}

---

## 5. Plan of Action and Milestones (POA&M)

*Actionable steps for the engineering and security teams to resolve the gap.*

- [ ] **Phase 1 (Immediate):** {IMMEDIATE_ACTION}
- [ ] **Phase 2 (Short-Term):** {SHORT_TERM_ACTION}
- [ ] **Phase 3 (Long-Term/Strategic):** {LONG_TERM_ACTION}
````

---

## FILE: `threat_assessment_skill.md` (sha256=49a307e936385d51559bf19e00c6a58bb2f0a12cb933849080f6501dba46229f)

````markdown
---
name: Generate Zero Trust Threat Assessment
description: Analyzes unstructured threat intelligence or blue team reports, queries the MITRE/ZIG Knowledge Graph, and generates a structured Plan of Action (POA&M) mitigation report.
---

# Generate Zero Trust Threat Assessment

You are an expert Cybersecurity AI Agent. Your objective is to ingest unstructured threat intelligence or network assessment data, translate it into standard MITRE and NSA Zero Trust frameworks, and output a highly structured remediation plan.

To accomplish this, you must use the Python `KnowledgeGraphEngine` provided in the `scripts/graph_engine.py` file. Note: `semantic_search()` always returns `(node_id, node_data, score)` 3-tuples — in semantic mode AND in the air-gapped keyword-fallback mode. A `[Warning] Semantic search unavailable...` message means the fallback is active; that is normal, not an error.

> **CRITICAL INSTRUCTION: NARROW SCOPE**
> Do not generate a single, massive, monolithic report for a large dataset. You must generate a **series of individual, narrowly focused Action Plans**. Each output report should cover only a single finding (or a very small handful of closely related correlations).

> **CRITICAL INSTRUCTION: FORMATTING**
> Do NOT use emojis in your output. Ensure that the primary MITRE mapping is ALWAYS an ATT&CK Technique (T-code), supplemented by Analytics and Mitigations.

## Execution Workflow

Follow these exact steps when a user provides you with threat data:

### Step 1: Entity Extraction
Read the unstructured threat report provided by the user. Identify the core technical actions, vulnerabilities, or attacker behaviors (e.g., "bypassed authentication," "forged Kerberos tickets," "lateral movement").

### Step 2: Graph Mapping
Map the extracted behaviors strictly to a MITRE ATT&CK **Technique** (T-code).
Write and execute a Python script that instantiates `KnowledgeGraphEngine()` and calls `engine.semantic_search(text, top_k=20)`.
- You MUST filter the returned results to the highest-scoring node whose ID starts with `T` followed by a digit (e.g., `T1558.001`). Do not map the primary finding to an Analytic (`AN...`), Mitigation (`M...`), or Detection Strategy (`DET...`).
- The same call works in air-gapped mode (it internally routes to `engine.keyword_rank()`); you do not need a separate code path.

### Step 3: Mitigation Crawling
Once you have the starting MITRE Technique node, crawl the graph for connected defenses: `engine.crawl_subgraph(node_id, depth=2)`.
From the returned subgraph's `nodes`, collect by `type` attribute:
- `d3fend_technique` — D3FEND countermeasures (e.g., Credential Rotation)
- `defensive_artifact` / `attack_datacomponent` — artifacts to monitor or protect
- `attack_analytic` — detections (their useful text is in the `description` field, not `name`)
- `attack_mitigation` — native ATT&CK mitigations

### Step 4: Zero Trust (ZIG) Correlation
Map the D3FEND countermeasures to NSA Zero Trust (ZIG) capabilities and technologies.
Use `engine.keyword_rank(countermeasure_name, top_k=100)` with the countermeasure's plain name (e.g., "Credential Rotation" — never the "[D3-CRO] Credential Rotation" formatted string), then filter results for `type == 'zig_capability'` and `type == 'zig_technology'`.
Resolve the capability's pillar by following its `belongs_to_pillar` edge, and optionally crawl the capability (`engine.crawl_subgraph(zig_cap_id, depth=2)`) for its activities and implementing technologies.

### Step 5: Assessment Generation
Compile all the information you gathered from the graph engine.
Format your final output strictly according to the structure defined in `assessment_template.md`, filling EVERY placeholder.
Pay special attention to the **"So What?"** section:
1. Executive Summary (Must include the Threat Actor Exploitation & Impact)
2. MITRE Framework Analysis
3. NSA ZIG Alignment
4. Technology Recommendations
5. Plan of Action and Milestones (POA&M)

You write the Exploitation Scenario, Business Impact, and POA&M actions yourself from the finding's context — but **never invent MITRE techniques, D3FEND countermeasures, or ZIG capabilities. Always pull framework identifiers directly from the `KnowledgeGraphEngine` outputs.**

## Bulk Processing Shortcut
For large multi-tab reports, run `python3 scripts/ingest_assessment.py <report.xlsx>` to flatten all findings into `processed_assessment.csv`, then `python3 agent_batch_processor.py --limit N` to auto-generate draft reports in `mock_output/`. Treat those drafts as scaffolding: review each one and replace the heuristic Exploitation/Impact text with your own analysis.
````

---

## FILE: `consolidate_mitre_data.py` (sha256=134f68671af08c16eabc6b1ac7fee8ec19118a83167c312f500372e6f435e48b)

````python
import pandas as pd
import json
import re
import os

nodes = {} # id -> {id, type, name, description, url}
edges = set() # (source_id, target_id, relationship_type)

def add_node(id, type, name, description="", url=""):
    if pd.isna(id) or not id: return
    id = str(id).strip()
    if id not in nodes:
        nodes[id] = {
            "id": id,
            "type": type,
            "name": str(name).strip() if pd.notna(name) else "",
            "description": str(description).strip() if pd.notna(description) else "",
            "url": str(url).strip() if pd.notna(url) else ""
        }

def add_edge(source_id, target_id, rel_type):
    if pd.isna(source_id) or pd.isna(target_id) or not source_id or not target_id: return
    edges.add((str(source_id).strip(), str(target_id).strip(), str(rel_type).strip()))

print("Parsing enterprise-attack-v19.1(1).xlsx...")
attack_xls = pd.ExcelFile('enterprise-attack-v19.1(1).xlsx')

# Parse Tactics first so we can map tactic names -> TA IDs on technique edges
print(" - tactics")
df_tac = attack_xls.parse('tactics')
tactic_name_to_id = {}
for _, row in df_tac.iterrows():
    add_node(row['ID'], 'attack_tactic', row['name'], row.get('description'), row.get('url'))
    tactic_name_to_id[str(row['name']).strip().lower()] = str(row['ID']).strip()

# Parse Techniques
print(" - techniques")
df_tech = attack_xls.parse('techniques')
for _, row in df_tech.iterrows():
    add_node(row['ID'], 'attack_technique', row['name'], row.get('description'), row.get('url'))
    if pd.notna(row.get('tactics')):
        # The 'tactics' column holds tactic NAMES (e.g. "Privilege Escalation").
        # Resolve them to TA-IDs so the edge points at a real node.
        for tactic in str(row['tactics']).split(','):
            tactic_id = tactic_name_to_id.get(tactic.strip().lower())
            if tactic_id:
                add_edge(row['ID'], tactic_id, 'belongs_to_tactic')
    if pd.notna(row.get('sub-technique of')):
        add_edge(row['ID'], row['sub-technique of'], 'subtechnique_of')

# Parse Mitigations
print(" - mitigations")
df_mit = attack_xls.parse('mitigations')
for _, row in df_mit.iterrows():
    add_node(row['ID'], 'attack_mitigation', row['name'], row.get('description'), row.get('url'))

# Parse Groups / Software / Campaigns (sources of the 'uses' relationships)
for sheet, node_type in [('groups', 'attack_group'), ('software', 'attack_software'), ('campaigns', 'attack_campaign')]:
    print(f" - {sheet}")
    df_s = attack_xls.parse(sheet)
    for _, row in df_s.iterrows():
        add_node(row['ID'], node_type, row['name'], row.get('description'), row.get('url'))

# Parse Data Components
print(" - datacomponents")
df_dc = attack_xls.parse('datacomponents')
for _, row in df_dc.iterrows():
    add_node(row['ID'], 'attack_datacomponent', row['name'], row.get('description'), row.get('url'))

# Parse Detection Strategies (sources of the 'detects' relationships)
print(" - detectionstrategies")
df_ds = attack_xls.parse('detectionstrategies')
for _, row in df_ds.iterrows():
    add_node(row['ID'], 'attack_detectionstrategy', row['name'], "", row.get('url'))

# Parse Analytics (build STIX-ID -> AN-ID map for the defensive mappings sheet)
print(" - analytics")
df_an = attack_xls.parse('analytics')
analytic_stix_to_id = {}
for _, row in df_an.iterrows():
    add_node(row['ID'], 'attack_analytic', row['name'], row.get('description'), row.get('url'))
    if pd.notna(row.get('STIX ID')):
        analytic_stix_to_id[str(row['STIX ID']).strip()] = str(row['ID']).strip()

# Parse Defensive Mappings: DetectionStrategy -> Analytic -> DataComponent
print(" - defensive mappings")
df_dm = attack_xls.parse('defensive mappings')
for _, row in df_dm.iterrows():
    det_id = row.get('detection_strategy_attack_id')
    an_id = analytic_stix_to_id.get(str(row.get('analytic_id')).strip())
    dc_id = row.get('data_component_attack_id')
    if pd.notna(det_id) and an_id:
        add_edge(det_id, an_id, 'has_analytic')
    if an_id and pd.notna(dc_id):
        add_edge(an_id, dc_id, 'monitors_data_component')

# Parse ATT&CK Relationships (uses / mitigates / detects / attributed-to)
print(" - relationships")
df_rel = attack_xls.parse('relationships')
for _, row in df_rel.iterrows():
    source_id = row.get('source ID')
    target_id = row.get('target ID')
    rel_type = row.get('mapping type')
    if pd.notna(source_id) and pd.notna(target_id):
        add_edge(source_id, target_id, rel_type)

print("Parsing d3fend.csv...")
df_d3 = pd.read_csv('d3fend.csv')
d3fend_tech_name_to_id = {}
for _, row in df_d3.iterrows():
    tech_id = row.get('ID')
    tactic_name = row.get('D3FEND Tactic')
    # The technique name lives in one of three hierarchy columns depending on depth
    tech_name = row.get('D3FEND Technique')
    if pd.isna(tech_name): tech_name = row.get('D3FEND Technique Level 0')
    if pd.isna(tech_name): tech_name = row.get('D3FEND Technique Level 1')
    desc = row.get('Definition')
    if pd.notna(tech_id):
        tech_id_str = str(tech_id).strip()
        add_node(tech_id_str, 'd3fend_technique', tech_name, desc)

        if pd.notna(tech_name):
            d3fend_tech_name_to_id[str(tech_name).strip().lower()] = tech_id_str

        if pd.notna(tactic_name):
            tactic_id = "D3-TAC-" + str(tactic_name).replace(" ", "-").upper()
            add_node(tactic_id, 'd3fend_tactic', tactic_name)
            add_edge(tech_id_str, tactic_id, 'belongs_to_tactic')

print("Parsing ATT&CK_D3FEND_Mappings.ods...")
try:
    mappings_xls = pd.ExcelFile('ATT&CK_D3FEND_Mappings.ods', engine='odf')
    df_map = mappings_xls.parse('Sheet1')
    for _, row in df_map.iterrows():
        attack_id = row.get('ATT&CK ID')
        d3fend_techs = row.get('Related D3FEND Techniques')
        if pd.notna(attack_id) and pd.notna(d3fend_techs):
            # Cells contain concatenated "D3-CODE Name" entries with no separator,
            # so extract the D3 codes directly (they match d3fend.csv IDs).
            for dt_id in re.findall(r'D3-[A-Z0-9]+', str(d3fend_techs)):
                add_edge(attack_id, dt_id, 'mapped_to_d3fend_technique')
except Exception as e:
    print("Warning: Could not parse ATT&CK_D3FEND_Mappings.ods:", e)

print("Parsing d3fend-full-mappings.csv...")
df_full_map = pd.read_csv('d3fend-full-mappings.csv')
for _, row in df_full_map.iterrows():
    def_tech = row.get('def_tech_label')
    def_tactic = row.get('def_tactic_label')
    def_artifact = row.get('def_artifact_label')
    off_artifact = row.get('off_artifact_label')
    off_tech_id = row.get('off_tech_id')

    # Relationships
    def_artifact_rel = row.get('def_artifact_rel_label')
    off_artifact_rel = row.get('off_artifact_rel_label')

    if pd.notna(def_tech):
        dt_lower = str(def_tech).strip().lower()
        dt_id = d3fend_tech_name_to_id.get(dt_lower, "D3-" + str(def_tech).replace(" ", "-").upper())
        add_node(dt_id, 'd3fend_technique', def_tech)

        if pd.notna(def_tactic):
            tac_id = "D3-TAC-" + str(def_tactic).replace(" ", "-").upper()
            add_node(tac_id, 'd3fend_tactic', def_tactic)
            add_edge(dt_id, tac_id, 'belongs_to_tactic')

        if pd.notna(def_artifact):
            da_id = "DA-" + str(def_artifact).replace(" ", "-").upper()
            add_node(da_id, 'defensive_artifact', def_artifact)
            add_edge(dt_id, da_id, def_artifact_rel if pd.notna(def_artifact_rel) else 'relates_to')

            if pd.notna(off_artifact):
                oa_id = "OA-" + str(off_artifact).replace(" ", "-").upper()
                add_node(oa_id, 'offensive_artifact', off_artifact)
                add_edge(da_id, oa_id, 'targets')

                if pd.notna(off_tech_id):
                    add_edge(oa_id, off_tech_id, off_artifact_rel if pd.notna(off_artifact_rel) else 'used_by')

# Integrity pass: drop any edge whose endpoint is not a real node. Without this,
# NetworkX silently creates attribute-less phantom nodes for every unknown ID.
before = len(edges)
edges = {e for e in edges if e[0] in nodes and e[1] in nodes}
dropped = before - len(edges)
if dropped:
    print(f"Integrity pass: dropped {dropped} edges referencing unknown node IDs ({len(edges)} remain).")

print("Exporting to mitre_nodes.csv and mitre_edges.csv...")
df_nodes = pd.DataFrame(list(nodes.values()))
df_nodes.to_csv('mitre_nodes.csv', index=False)

df_edges = pd.DataFrame(list(edges), columns=['source_id', 'target_id', 'relationship_type'])
df_edges.to_csv('mitre_edges.csv', index=False)

print("Exporting to ontology.json...")
ontology = {
    "nodes": list(nodes.values()),
    "edges": [{"source_id": e[0], "target_id": e[1], "relationship_type": e[2]} for e in edges]
}
with open('ontology.json', 'w') as f:
    json.dump(ontology, f, indent=2)

print(f"Done! Exported {len(nodes)} nodes and {len(edges)} edges.")
````

---

## FILE: `scripts/parse_zig_data.py` (sha256=5e16d679ada7cd252d578012ed9214556034269af719f8f6d976f7a1bac66617)

````python
import re
import csv
import os

PILLARS = {
    1: "User",
    2: "Device",
    3: "Application and Workload",
    4: "Data",
    5: "Network and Environment",
    6: "Automation and Orchestration",
    7: "Visibility and Analytics"
}

def parse_zig_text_files(files):
    capabilities = {}
    activities = {}

    cap_pattern = re.compile(r'^Capability\s+(\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$')
    act_pattern = re.compile(r'^Activity\s+(\d+\.\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$')

    for fpath in files:
        if not os.path.exists(fpath):
            continue
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Check for Capability
                c_match = cap_pattern.search(line)
                if c_match:
                    c_id = c_match.group(1)
                    c_name = c_match.group(2).strip()
                    # Strip trailing dots and page numbers if any
                    c_name = re.sub(r'\s*\.{2,}\s*\d*$', '', c_name).strip()
                    if c_id not in capabilities or len(c_name) > len(capabilities[c_id]): 
                        capabilities[c_id] = c_name
                
                # Check for Activity
                a_match = act_pattern.search(line)
                if a_match:
                    a_id = a_match.group(1)
                    a_name = a_match.group(2).strip()
                    a_name = re.sub(r'\s*\.{2,}\s*\d*$', '', a_name).strip()
                    if a_id not in activities or len(a_name) > len(activities[a_id]):
                        activities[a_id] = a_name

    return capabilities, activities

def parse_tech_mappings(fpath):
    mappings = []
    technologies = {}
    tech_id_counter = 1
    
    with open(fpath, 'r', encoding='utf-8') as f:
        lines = f.read().strip().split('\n')
        
    i = 0
    while i < len(lines):
        tech_name = lines[i].strip()
        if not tech_name:
            i += 1
            continue
        if i + 1 >= len(lines):
            break
            
        caps_line = lines[i+1].strip()
        count_line = lines[i+2].strip() if i + 2 < len(lines) else ""
        
        # Extract capabilities like 4.4P45.1P5 -> 4.4, 5.1
        caps = re.findall(r'(\d+\.\d+)P\d', caps_line)
        
        tech_id = f"ZIG-TECH-{tech_id_counter}"
        technologies[tech_id] = tech_name
        tech_id_counter += 1
        
        for cap in caps:
            mappings.append((tech_id, cap))
            
        i += 3
        
    return technologies, mappings

def generate_csvs(capabilities, activities, technologies, tech_mappings):
    nodes = []
    edges = []
    
    # Add Pillars
    for p_id, p_name in PILLARS.items():
        node_id = f"ZIG-PIL-{p_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_pillar",
            "name": f"{p_name} Pillar",
            "description": f"ZIG {p_name} Pillar",
            "url": ""
        })
        
    # Add Capabilities
    for c_id, c_name in capabilities.items():
        node_id = f"ZIG-CAP-{c_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_capability",
            "name": c_name,
            "description": f"ZIG Capability {c_id}",
            "url": ""
        })
        p_id = c_id.split('.')[0]
        edges.append({
            "source_id": node_id,
            "target_id": f"ZIG-PIL-{p_id}",
            "relationship_type": "belongs_to_pillar"
        })
        
    # Add Activities
    for a_id, a_name in activities.items():
        node_id = f"ZIG-ACT-{a_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_activity",
            "name": a_name,
            "description": f"ZIG Activity {a_id}",
            "url": ""
        })
        c_id = ".".join(a_id.split('.')[:2])
        edges.append({
            "source_id": node_id,
            "target_id": f"ZIG-CAP-{c_id}",
            "relationship_type": "belongs_to_capability"
        })
        
    # Add Technologies
    for t_id, t_name in technologies.items():
        nodes.append({
            "id": t_id,
            "type": "zig_technology",
            "name": t_name,
            "description": f"ZIG Technology Mapping",
            "url": ""
        })
        
    # Add Tech Mappings
    for t_id, c_id in tech_mappings:
        # Note: some capabilities might not be parsed if they aren't in the PDFs 
        # but are in the tech mappings (e.g. Discovery phase might have missed some).
        # We will create edges regardless.
        edges.append({
            "source_id": t_id,
            "target_id": f"ZIG-CAP-{c_id}",
            "relationship_type": "implements_capability"
        })
        
    # Write nodes.csv
    with open('zig_nodes.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["id", "type", "name", "description", "url"])
        writer.writeheader()
        writer.writerows(nodes)
        
    # Write edges.csv
    with open('zig_edges.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["source_id", "target_id", "relationship_type"])
        writer.writeheader()
        writer.writerows(edges)
        
if __name__ == "__main__":
    txt_files = [
        "CTR_ZIG_DISCOVERY_PHASE.PDF.txt",
        "CTR_ZIG_PHASE_ONE.PDF.txt",
        "CTR_ZIG_PHASE_TWO.PDF.txt"
    ]
    caps, acts = parse_zig_text_files(txt_files)
    techs, mappings = parse_tech_mappings("zig_tech_mappings.txt")
    
    generate_csvs(caps, acts, techs, mappings)
    print(f"Parsed {len(caps)} capabilities and {len(acts)} activities.")
    print(f"Parsed {len(techs)} technologies with {len(mappings)} mappings.")
    print("Generated zig_nodes.csv and zig_edges.csv.")
````

---

## FILE: `import_to_neo4j.py` (sha256=c96e1eda600630e470b047875d8490f039f3b428d28e2126903ef301a4dc61c0)

````python
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
````

---

## FILE: `build_deployment_guide.py` (sha256=0c085f6624ab1f500f326601791eac85c80fea165cbabcb07e2ad7665b8c0d26)

````python
"""Regenerates Air_Gapped_Deployment_Guide.md from the ACTUAL files on disk.

The guide embeds full copies of every source file, so a coding agent on the
air-gapped network can recreate the entire system from the guide alone.
Because the guide is generated from the real files, it can never drift out
of sync with the code the way a hand-maintained guide can.

Run this after ANY change to the scripts or template:
    python3 build_deployment_guide.py
"""
import csv
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Files embedded in the guide, in the order a recreating agent should write them.
EMBEDDED_FILES = [
    ("scripts/graph_engine.py", "python"),
    ("scripts/embed_graph.py", "python"),
    ("scripts/ingest_assessment.py", "python"),
    ("agent_batch_processor.py", "python"),
    ("agent_crawl_example.py", "python"),
    ("assessment_template.md", "markdown"),
    ("requirements.txt", "text"),
]

# Only needed when the pre-built CSVs could NOT be ported and the raw
# source files (ATT&CK xlsx, D3FEND csv, ZIG PDFs) were ported instead.
REGEN_FILES = [
    ("consolidate_mitre_data.py", "python"),
    ("scripts/parse_zig_data.py", "python"),
]


def count_csv(path):
    with open(os.path.join(BASE_DIR, path), encoding="utf-8") as f:
        return sum(1 for _ in csv.DictReader(f))


def graph_counts():
    """Deduplicated counts as the engine will actually report them."""
    import networkx as nx
    g = nx.DiGraph()
    for nodes_file, edges_file in [("mitre_nodes.csv", "mitre_edges.csv"),
                                   ("zig_nodes.csv", "zig_edges.csv")]:
        with open(os.path.join(BASE_DIR, nodes_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_node(row["id"])
        with open(os.path.join(BASE_DIR, edges_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_edge(row["source_id"], row["target_id"])
    return g.number_of_nodes(), g.number_of_edges()


def embed(relpath, lang):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        content = f.read().rstrip()
    return f"### FILE: `{relpath}`\n\n```{lang}\n{content}\n```\n"


def main():
    mitre_nodes = count_csv("mitre_nodes.csv")
    mitre_edges = count_csv("mitre_edges.csv")
    zig_nodes = count_csv("zig_nodes.csv")
    zig_edges = count_csv("zig_edges.csv")
    total_nodes, total_edges = graph_counts()

    code_sections = "\n---\n\n".join(embed(p, lang) for p, lang in EMBEDDED_FILES)
    regen_sections = "\n---\n\n".join(embed(p, lang) for p, lang in REGEN_FILES)

    guide = GUIDE_TEMPLATE.format(
        mitre_nodes=mitre_nodes, mitre_edges=mitre_edges,
        zig_nodes=zig_nodes, zig_edges=zig_edges,
        total_nodes=total_nodes, total_edges=total_edges,
        code_sections=code_sections, regen_sections=regen_sections,
    )

    out = os.path.join(BASE_DIR, "Air_Gapped_Deployment_Guide.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out}")
    print(f"Verification numbers baked in: {total_nodes} nodes / {total_edges} edges "
          f"(MITRE {mitre_nodes}/{mitre_edges}, ZIG {zig_nodes}/{zig_edges})")


GUIDE_TEMPLATE = '''# Air-Gapped Deployment Guide & Agent Reconstruction Plan

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> Your task is to stand up a Python-based threat-intelligence knowledge graph on this
> air-gapped network. The system maps unstructured red/blue team findings to MITRE
> ATT&CK techniques, D3FEND countermeasures, and NSA Zero Trust (ZIG) capabilities,
> then generates standardized POA&M reports.
>
> **Follow this document top to bottom. Do not improvise, do not "improve" the code,
> and do not skip verification steps.** Every source file you need is embedded below
> in full — copy each one byte-for-byte. After every stage, run the listed
> verification command and compare against the expected output before moving on.
> If a verification fails, stop and fix that stage; later stages depend on it.

---

## 1. What This System Is

Three cooperating pieces, all plain Python:

1. **Knowledge Graph Engine** (`scripts/graph_engine.py`) — loads four CSVs into a
   NetworkX directed graph ({total_nodes} nodes, {total_edges} edges) unifying
   MITRE ATT&CK, MITRE D3FEND, and the NSA Zero Trust Implementation Guide (ZIG).
   Exposes `query_node`, `search_nodes`, `keyword_rank`, `semantic_search`,
   `get_neighbors`, and `crawl_subgraph`.
2. **Ingestion pipeline** (`scripts/ingest_assessment.py`) — flattens messy
   multi-tab Excel/CSV assessment reports (any column schema) into
   `processed_assessment.csv`, optionally with vector embeddings.
3. **Report generator** (`agent_batch_processor.py`) — walks each finding through
   the graph (technique → countermeasures → ZIG capabilities → technologies) and
   fills in `assessment_template.md` to produce one POA&M report per finding.

**Graceful degradation is a core design requirement.** If the machine-learning
libraries (`numpy`, `scikit-learn`, `sentence-transformers`) cannot be installed
on this network, the engine catches the `ImportError` and transparently routes
`semantic_search()` through `keyword_rank()` — a stopword-filtered, token-scored
keyword search that works on full sentences. **The absence of ML libraries is an
expected, supported configuration, not an error.** `semantic_search()` returns
`(node_id, node_data, score)` 3-tuples in BOTH modes, so calling code never
needs to know which mode is active.

---

## 2. Asset Manifest — what to port, in priority order

| Priority | Asset | Size | Why |
|---|---|---|---|
| 1 | The four graph CSVs: `mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`, `zig_edges.csv` | ~8 MB | The knowledge graph itself. Without these you must regenerate from raw sources (Section 7). |
| 2 | This guide | ~150 KB | Contains every source file in full. |
| 3 | `graph_embeddings.npz` + `embedding_metadata.json` | ~8 MB | Pre-computed node vectors. Saves re-running `embed_graph.py`, but semantic mode still needs item 4 to encode queries. |
| 4 | HuggingFace model cache dir `models--sentence-transformers--all-MiniLM-L6-v2` (from `~/.cache/huggingface/hub/`) | ~90 MB | Required to embed NEW text (queries, new assessments) in semantic mode. |
| 5 | Python wheels: `networkx`, `pandas`, `openpyxl`, `odfpy`; optionally `numpy`, `scikit-learn`, `sentence-transformers` (+torch) | varies | Tier 1–2 are small and mandatory; Tier 3 is ~2 GB with torch and optional. |
| 6 | Raw sources: `enterprise-attack-v19.1(1).xlsx`, `d3fend.csv`, `d3fend-full-mappings.csv`, `ATT&CK_D3FEND_Mappings.ods`, ZIG PDF text extracts | ~40 MB | Only needed if item 1 could not be ported. |

**Decision tree:**

- Ported the CSVs (item 1)? → Do Sections 3–6. Skip Section 7.
- No CSVs, but raw sources (item 6)? → Do Sections 3–4, then Section 7, then 5–6.
- Have ML wheels AND the model cache (items 4–5)? → Semantic mode. Run `scripts/embed_graph.py` once (Section 5).
- No ML wheels, or no model cache? → Keyword-fallback mode. Skip Section 5 entirely; everything still works.

---

## 3. Directory Layout

Create exactly this structure (files marked * are generated later, not created by hand):

```text
MITRE_CSD-H/
├── mitre_nodes.csv            # ported or generated by consolidate_mitre_data.py
├── mitre_edges.csv            # ported or generated
├── zig_nodes.csv              # ported or generated by scripts/parse_zig_data.py
├── zig_edges.csv              # ported or generated
├── assessment_template.md
├── requirements.txt
├── agent_batch_processor.py
├── agent_crawl_example.py
├── graph_embeddings.npz       # * optional, semantic mode only
├── embedding_metadata.json    # * optional, semantic mode only
├── processed_assessment.csv   # * output of ingest_assessment.py
├── mock_output/               # * generated reports land here
└── scripts/
    ├── graph_engine.py
    ├── embed_graph.py
    └── ingest_assessment.py
```

Install dependencies (Tier 1 is mandatory, others per the decision tree):

```bash
pip install networkx pandas          # Tier 1 — required
pip install openpyxl odfpy           # Tier 2 — only to read Excel/ODS inputs
pip install numpy scikit-learn sentence-transformers   # Tier 3 — OPTIONAL semantic mode
```

---

## 4. Source Files (copy each verbatim)

{code_sections}

---

## 5. OPTIONAL — Semantic Mode Setup

Skip this section entirely if Tier 3 libraries are unavailable. The system is
fully functional in keyword-fallback mode.

**5.1 Port the embedding model.** `SentenceTransformer('all-MiniLM-L6-v2')`
normally downloads from the internet, which will fail here. Copy the cached
model directory from the low side:

```text
LOW SIDE:  ~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/   (~90 MB)
HIGH SIDE: same path under the service account's home directory
```

Then force offline resolution so the library never attempts a network call:

```bash
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
```

(Alternative: place the model folder anywhere and change every
`SentenceTransformer('all-MiniLM-L6-v2')` call to
`SentenceTransformer('/absolute/path/to/model-dir')` — it appears once each in
`graph_engine.py`, `embed_graph.py`, and `ingest_assessment.py`.)

**5.2 Generate graph embeddings** (once, and again whenever the CSVs change).
If `graph_embeddings.npz` + `embedding_metadata.json` were ported, you may skip
this — but you MUST regenerate them if you regenerated the CSVs in Section 7,
because the vector row order must match the node list.

```bash
python3 scripts/embed_graph.py
```

Expected: a progress bar, then
`Successfully saved embeddings to .../graph_embeddings.npz ...`.

---

## 6. VERIFICATION — run after setup, before first real use

**6.1 Engine loads and both frameworks are present:**

```bash
python3 scripts/graph_engine.py
```

Expected output (numbers must match within a few units if you ported the CSVs;
they will differ slightly if MITRE releases new data):

```text
Knowledge Graph initialized with {total_nodes} nodes and {total_edges} edges.

Test: Querying a ZIG Pillar
{{'id': 'ZIG-PIL-1', 'type': 'zig_pillar', 'name': 'User Pillar', ...}}

Test: Querying a MITRE node (e.g. T1548)
{{'id': 'T1548', 'type': 'attack_technique', 'name': 'Abuse Elevation Control Mechanism', ...}}

Test: Search (semantic if available, keyword fallback otherwise)
  [T...] ... (score: ...)
```

Reference counts: MITRE = {mitre_nodes} nodes / {mitre_edges} edges,
ZIG = {zig_nodes} nodes / {zig_edges} edges.

**6.2 Search returns 3-tuples in whichever mode is active:**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
r = e.semantic_search('attacker dumped password hashes from memory', top_k=5)
assert r and len(r[0]) == 3, 'search must return (id, data, score) 3-tuples'
for nid, data, score in r: print(nid, data.get('name'), round(score, 3))
"
```

Expected: 5 rows; credential-dumping-related techniques/analytics near the top
(e.g. `T1003.001 OS Credential Dumping: LSASS Memory`). In keyword-fallback mode
you will first see a `[Warning] Semantic search unavailable...` line — that is
correct behavior, not an error.

**6.3 End-to-end pipeline on mock data.** Create a small test CSV, then run:

```bash
python3 - <<'EOF'
import pandas as pd
pd.DataFrame({{
    "IP": ["192.168.1.15", "10.0.50.5"],
    "Hostname": ["DC-01", "EDGE-RTR-01"],
    "Finding": ["Kerberos Pre-Authentication disabled on service accounts",
                 "Weak administrative password set"],
    "Severity": ["High", "Critical"],
}}).to_csv("mock_assessment_data.csv", index=False)
EOF
python3 scripts/ingest_assessment.py mock_assessment_data.csv
python3 agent_batch_processor.py --limit 2
```

Expected: `Generated .../mock_output/ASMT-1000.md -> Mapped to T... & ZIG-CAP-...`
for each finding. Open a generated report and confirm: every section is filled,
every MITRE/D3FEND/ZIG identifier in it exists in the graph (spot-check with
`engine.query_node(...)`), and no section contains invented framework IDs.

---

## 7. ONLY IF CSVs WERE NOT PORTED — regenerate from raw sources

Requires the raw files from Asset Manifest item 6 in the repo root, plus Tier 2
libraries. Create the two scripts below, then run:

```bash
python3 consolidate_mitre_data.py      # → mitre_nodes.csv, mitre_edges.csv, ontology.json
cd raw_data/zig 2>/dev/null || true    # parse_zig_data.py expects the ZIG .txt files in its cwd
python3 scripts/parse_zig_data.py      # → zig_nodes.csv, zig_edges.csv (move them to repo root)
```

Notes for the agent:
- `consolidate_mitre_data.py` ends with an integrity pass that drops edges
  referencing unknown node IDs. A small number of dropped edges (tens, not
  hundreds) is normal.
- The ZIG parser reads text extracted from the NSA ZIG PDFs
  (`CTR_ZIG_*.PDF.txt`) plus `zig_tech_mappings.txt`. If only the PDFs are
  available, extract text first (any PDF-to-text tool; `pdfplumber` works).
- After regenerating CSVs, regenerate embeddings (Section 5.2) if in semantic mode.

{regen_sections}

---

## 8. Graph Reference (for writing queries)

**Node ID prefixes / types:**

| Prefix | `type` attribute | Framework |
|---|---|---|
| `T`, `T....XXX` | `attack_technique` | ATT&CK technique / sub-technique |
| `TA` | `attack_tactic` | ATT&CK tactic |
| `M1` | `attack_mitigation` | ATT&CK mitigation |
| `G` / `S` / `C` | `attack_group` / `attack_software` / `attack_campaign` | ATT&CK threat intel |
| `DET` | `attack_detectionstrategy` | ATT&CK detection strategy |
| `AN` | `attack_analytic` | ATT&CK analytic (name is generic; the useful text is in `description`) |
| `DC` | `attack_datacomponent` | ATT&CK data component |
| `D3-` | `d3fend_technique` | D3FEND countermeasure |
| `D3-TAC-` | `d3fend_tactic` | D3FEND tactic |
| `DA-` / `OA-` | `defensive_artifact` / `offensive_artifact` | D3FEND artifacts |
| `ZIG-PIL-` / `ZIG-CAP-` / `ZIG-ACT-` / `ZIG-TECH-` | `zig_pillar` / `zig_capability` / `zig_activity` / `zig_technology` | NSA Zero Trust |

**Key relationship types:** `belongs_to_tactic`, `subtechnique_of`, `uses`
(group/software/campaign → technique), `mitigates` (M → T), `detects` (DET → T),
`has_analytic` (DET → AN), `monitors_data_component` (AN → DC),
`mapped_to_d3fend_technique` (M → D3-), `targets` (DA → OA), plus D3FEND artifact
verbs (`accesses`, `modifies`, `creates`, ...), and ZIG's `belongs_to_pillar`,
`belongs_to_capability`, `implements_capability` (ZIG-TECH → ZIG-CAP).

**CSV schemas:** node files are `id,type,name,description,url`; edge files are
`source_id,target_id,relationship_type`.

---

## 9. Agent Workflow: From Threat Intel to Remediation Plan

When a user hands you unstructured findings, do this per finding (this is what
`agent_batch_processor.py` automates — read it as the reference implementation):

1. **Extract** the core technical behavior from the text (e.g. "forged Kerberos tickets").
2. **Map** it to an ATT&CK technique: `engine.semantic_search(text, top_k=20)`,
   then take the highest-scoring result whose ID starts with `T` followed by a
   digit. Never map the primary finding to an `AN`, `M`, or `DET` node.
3. **Crawl** for defenses: `engine.crawl_subgraph(t_code, depth=2)`. From the
   returned nodes collect `d3fend_technique` (countermeasures),
   `defensive_artifact`/`attack_datacomponent` (artifacts), `attack_analytic`
   (detections — quote their `description`), `attack_mitigation`.
4. **Correlate to Zero Trust:** `engine.keyword_rank(countermeasure_name, top_k=100)`,
   filter for `zig_capability` and `zig_technology`. Resolve the capability's
   pillar via its `belongs_to_pillar` edge.
5. **Generate** one narrowly-scoped report per finding by filling EVERY
   placeholder in `assessment_template.md`. Write the Exploitation Scenario /
   Impact / POA&M text yourself from the finding's context. **Never invent
   MITRE, D3FEND, or ZIG identifiers — only use IDs returned by the engine.**
   No emojis in reports.

For bulk processing: `python3 scripts/ingest_assessment.py <report.xlsx>` then
`python3 agent_batch_processor.py --limit N` — then review and enrich the
generated reports (the batch script's Exploitation/Impact text is heuristic;
replace it with your own analysis).

---

## 10. Using an Internal Embedding API Instead of a Local Model

If ML libraries exist high-side but the model cannot be hosted locally, point
the two `encode` call sites at your internal embeddings endpoint:

1. **`scripts/embed_graph.py`** — replace `model.encode(texts_to_embed, ...)`
   with a loop that POSTs each text to the API and collects vectors into
   `embeddings = np.array(list_of_vectors)`.
2. **`scripts/graph_engine.py` → `semantic_search()`** — replace
   `self.embedding_model.encode([query_text])` with one API call. The result
   must be a 2-D array: `query_vec = np.array([vector])`.

Both files contain `EXTERNAL API SCAFFOLDING` comment blocks marking the exact
lines. The cosine-similarity ranking is unchanged. All vectors (graph and
query) must come from the SAME model — never mix local and API embeddings.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Knowledge Graph initialized with 0 nodes` | CSVs missing from the repo root (the engine resolves them relative to its own file, so cwd is not the issue) | Put the four CSVs next to `scripts/`' parent, i.e. the repo root |
| `[Warning] Semantic search unavailable...` | Tier 3 libs or embedding files absent | Expected in keyword-fallback mode; ignore, or complete Section 5 |
| `SentenceTransformer` tries to download / times out | Model cache not ported or offline env vars unset | Section 5.1 |
| Search results are all `AN` analytics | You forgot to filter for `T`-prefixed IDs (workflow step 2) | Filter results |
| `KeyError` in `agent_batch_processor.py` template fill | `assessment_template.md` placeholders don't match — you edited one file but not the other | Diff the `template.format(...)` kwargs against the `{{PLACEHOLDER}}` names |
| Embedding search returns nonsense after CSV regeneration | Stale `graph_embeddings.npz` (row order no longer matches nodes) | Re-run `scripts/embed_graph.py` |

---

*This guide is generated by `build_deployment_guide.py` from the live source
files — regenerate it after any code change rather than editing it by hand.*
'''


if __name__ == "__main__":
    main()
````

---

## FILE: `README.md` (sha256=7d982161c2af579d242fddf8a6b9d60145b20183afb683c1e39e99da3943dec1)

````markdown
# MITRE CSD-H — Threat Intelligence Knowledge Graph & Assessment Engine

A property graph unifying **MITRE ATT&CK**, **MITRE D3FEND**, and the **NSA Zero
Trust Implementation Guide (ZIG)**, plus a Python engine and pipeline that let an
LLM agent translate unstructured red/blue team findings into standardized,
framework-mapped Plans of Action & Milestones (POA&M).

Designed for **air-gapped deployment**: if ML libraries are unavailable, semantic
search degrades automatically to ranked keyword search — see
`Air_Gapped_Deployment_Guide.md` for the full porting/reconstruction plan.

## What's in the graph

| Framework | Contents |
|---|---|
| ATT&CK v19.1 | Tactics, techniques, mitigations, groups, software, campaigns, data components, detection strategies, analytics |
| D3FEND | Countermeasure techniques, tactics, defensive & offensive artifacts, ATT&CK↔D3FEND mappings |
| NSA ZIG | Pillars, capabilities, activities, technology-to-capability mappings |

Node files (`*_nodes.csv`): `id,type,name,description,url`.
Edge files (`*_edges.csv`): `source_id,target_id,relationship_type`.
Everything also exports as a single `ontology.json`.

## Quick start

```bash
pip install -r requirements.txt      # Tier 1 lines are the only hard requirement

# Sanity-check the engine (loads mitre_*.csv + zig_*.csv from the repo root)
python3 scripts/graph_engine.py

# OPTIONAL semantic mode: generate node embeddings once
python3 scripts/embed_graph.py

# Process an assessment report (any-schema Excel/CSV) and generate POA&M reports
python3 scripts/ingest_assessment.py <report.xlsx>
python3 agent_batch_processor.py --limit 5      # reports land in mock_output/
```

An interactive walkthrough of the agent query pattern is in
`agent_crawl_example.py`; the LLM-agent prompt lives in
`threat_assessment_skill.md`.

## Key files

| File | Purpose |
|---|---|
| `scripts/graph_engine.py` | `KnowledgeGraphEngine` — load graph, `semantic_search` / `keyword_rank` / `crawl_subgraph` |
| `scripts/ingest_assessment.py` | Flattens multi-tab, arbitrary-schema assessment reports into `processed_assessment.csv` (+ optional embeddings) |
| `agent_batch_processor.py` | Batch: finding → T-code → D3FEND → ZIG → filled `assessment_template.md` |
| `consolidate_mitre_data.py` | Regenerates `mitre_nodes.csv` / `mitre_edges.csv` / `ontology.json` from the raw ATT&CK xlsx + D3FEND csv/ods |
| `scripts/parse_zig_data.py` | Regenerates `zig_nodes.csv` / `zig_edges.csv` from the ZIG PDF text extracts |
| `build_deployment_guide.py` | Regenerates `Air_Gapped_Deployment_Guide.md` from the live source files — run after any code change |
| `import_to_neo4j.py` | Optional Neo4j loader (nodes + typed relationships) |

## Regenerating the data

When MITRE releases new data, drop the updated raw files in the repo root and run:

```bash
python3 consolidate_mitre_data.py
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py       # keep the deployment guide in sync
```

## Using the graph elsewhere

- **Palantir Foundry/Gotham** — upload the node/edge CSVs; object type keyed on
  `id`, link type joining `source_id`/`target_id` → `id`.
- **Neo4j** — `python3 import_to_neo4j.py` (edit URI/credentials at the top), or
  `LOAD CSV` directly.
- **Python/NetworkX** — `from scripts.graph_engine import KnowledgeGraphEngine`.
- **Web dashboards / BI** — use `ontology.json` (Cytoscape.js, D3.js) or join the
  CSVs relationally (Tableau, PowerBI).
````


---

*Generated by `build_portable_bundle.py` from the live source files. Regenerate
after any code change; never edit this document by hand.*
