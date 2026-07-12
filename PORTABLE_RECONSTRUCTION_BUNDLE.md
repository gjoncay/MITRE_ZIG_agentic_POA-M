# PORTABLE RECONSTRUCTION BUNDLE — MITRE/ZIG Threat Assessment System

> **PROMPT — for the autonomous coding agent on the high-side network:**
> This single document contains the COMPLETE source code (15 files) of a
> Python threat-intelligence system, because the cross-domain transfer only
> permits text documents. Your job is to materialize the files, verify them
> against the checksums baked into this document, and stand the system up.
>
> **Rules:**
> 1. Do NOT retype or "reconstruct" the code from understanding — extract it
>    mechanically using STEP 0 below, so the checksums prove byte-exactness.
> 2. Do not modify, reformat, or "improve" any file.
> 3. Follow the sections in order and run every verification command.
> 4. The six data CSVs (`mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`,
>    `zig_edges.csv`, `cref_nodes.csv`, `cref_edges.csv`) are plain text and should
>    have been transferred alongside this document. If they are missing, see Section 5.

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
`15 files written, 0 checksum failures`. **If any line says FAIL, the
document was corrupted or altered in transfer (smart quotes, stripped
whitespace, line-ending conversion are the usual suspects) — do not proceed;
fix the transfer or fall back to careful manual copy of that one file, then
re-run the extractor to re-verify.**

## Extraction manifest

| File | Bytes | SHA-256 (first 16) |
|---|---|---|
| `requirements.txt` | 1523 | `9428c5dce50abae4...` |
| `scripts/graph_engine.py` | 9001 | `b1b5ae1df769b20c...` |
| `scripts/embed_graph.py` | 2187 | `87790cb1eb5f97b1...` |
| `scripts/ingest_assessment.py` | 6256 | `d46c9e8a2224d343...` |
| `agent_batch_processor.py` | 16655 | `03862d6b9ce4518a...` |
| `agent_crawl_example.py` | 7596 | `d3a08b5e7f4b38fe...` |
| `assessment_template.md` | 3272 | `f237e6ce6afe37ba...` |
| `threat_assessment_skill.md` | 8755 | `5be4cf80948c153b...` |
| `consolidate_mitre_data.py` | 8879 | `134f68671af08c16...` |
| `scripts/parse_zig_data.py` | 5861 | `5e16d679ada7cd25...` |
| `consolidate_cref_data.py` | 15424 | `2641d658cd3ec44e...` |
| `import_to_neo4j.py` | 2920 | `c96e1eda600630e4...` |
| `build_deployment_guide.py` | 24907 | `639688581709d122...` |
| `build_cref_extension_guide.py` | 16023 | `573aa373f5ac3e97...` |
| `README.md` | 8418 | `5c461835617fe545...` |

---

# STEP 1 — Assemble the data

Place the six CSVs (ported separately, as text) in the project root next to
`extract_bundle.py`. Expected layout after extraction + data placement:

```text
./
├── mitre_nodes.csv        ├── agent_batch_processor.py
├── mitre_edges.csv        ├── agent_crawl_example.py
├── zig_nodes.csv          ├── assessment_template.md
├── zig_edges.csv          ├── threat_assessment_skill.md
├── cref_nodes.csv         ├── consolidate_mitre_data.py
├── cref_edges.csv         ├── consolidate_cref_data.py
├── requirements.txt       ├── import_to_neo4j.py
├── README.md              ├── build_deployment_guide.py
└── build_cref_extension_guide.py
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

Must print `Knowledge Graph initialized with ~5618 nodes and ~43194 edges`
(small drift is fine if the CSVs were regenerated from newer MITRE/CREF data; a
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
`defensive_artifact`, `attack_analytic`, `attack_mitigation` node types).
Then: correlate to Zero Trust by checking the same subgraph for a direct
`zig_activity --mitigates--> T-code` edge first, falling back to
`keyword_rank(countermeasure_name)` only if none exists; correlate to CREF
architectural resiliency via `cref_approach --mitigates_architecturally--> T-code`;
cite NIST SP 800-53 controls via `cref_mitigation --satisfies_control--> control`;
and frame mission impact via the `csa --associated_with_technique--> cref_technique`
edge. Fill all 7 sections of `assessment_template.md` for EVERY finding — there is
no severity gate — never inventing framework IDs. Bulk mode:
`python3 scripts/ingest_assessment.py <report.xlsx>` then
`python3 agent_batch_processor.py --limit N`.

For the full reference documentation (asset tiers, graph schema tables,
troubleshooting), regenerate it locally:

```bash
python3 build_deployment_guide.py         # writes Air_Gapped_Deployment_Guide.md
python3 build_cref_extension_guide.py     # writes CREF_ZERO_TRUST_EXTENSION_GUIDE.md
```

---

# STEP 5 — ONLY if the CSVs did not survive transfer

The graph can be regenerated from raw MITRE/NSA/NIST sources IF they can be
obtained on this network (they are common on classified mirrors):
`enterprise-attack-v19.1(1).xlsx` (or newer), `d3fend.csv`,
`d3fend-full-mappings.csv`, `ATT&CK_D3FEND_Mappings.ods`, text extracts of
the NSA ZIG PDFs plus `zig_tech_mappings.txt`, and `CREF/*.csv`. Then (Tier 2
libs required: `pip install openpyxl odfpy`), IN THIS ORDER:

```bash
python3 consolidate_mitre_data.py    # -> mitre_nodes.csv, mitre_edges.csv
python3 scripts/parse_zig_data.py    # -> zig_nodes.csv, zig_edges.csv (run where the ZIG .txt files are)
python3 consolidate_cref_data.py     # -> cref_nodes.csv, cref_edges.csv; ALSO reconciles zig_nodes.csv/zig_edges.csv - run LAST
```

`consolidate_cref_data.py` reuses the existing `ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*`
IDs rather than duplicating the DoD Zero Trust pillar taxonomy, and cleans up
PDF-extraction artifacts in `zig_activity` names — do not re-run
`scripts/parse_zig_data.py` after it or you will overwrite that cleanup.

A few dropped edges reported by each integrity pass is normal (tens, not
hundreds). After regenerating, redo STEP 2, and STEP 3 if in semantic mode
(embeddings MUST be regenerated if `consolidate_cref_data.py` ran, since the
node set changed).

---

# EMBEDDED FILES

## FILE: `requirements.txt` (sha256=9428c5dce50abae45991edcaa2828679fcfab0431713967bf9d510bca67d58af)

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

# TIER 5 — OPTIONAL, enables real LLM-drafted narratives via scripts/llm_providers.py.
# LLM_PROVIDER=none (the default) needs neither of these and works with zero network
# access. LLM_PROVIDER=local (an OpenAI-compatible endpoint, e.g. Ollama/LM Studio —
# fine air-gapped, since it talks to a server on the local network, not the internet)
# and LLM_PROVIDER=openai both need `openai`. LLM_PROVIDER=gemini needs
# `google-generativeai` — this one always requires internet egress, so it is NOT
# usable on an air-gapped network regardless of whether the package is installed.
openai>=1.0
google-generativeai>=0.5
````

---

## FILE: `scripts/graph_engine.py` (sha256=b1b5ae1df769b20cd57e2d4b8df294a8af9444680ea8ff5d2390c09a4ce69bce)

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
        # Order matters: cref_edges.csv references node IDs defined in the mitre and
        # zig files (attack_technique, zig_activity), so it must load last.
        for nodes_file, edges_file in [('mitre_nodes.csv', 'mitre_edges.csv'),
                                       ('zig_nodes.csv', 'zig_edges.csv'),
                                       ('cref_nodes.csv', 'cref_edges.csv')]:
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

## FILE: `scripts/ingest_assessment.py` (sha256=d46c9e8a2224d343fb1b7378def81e9fec5d0b09c04a0938c5b7acaccbecac54)

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

def ingest_text(text, output_csv="processed_assessment.csv"):
    """Ingests a single pasted string of unstructured threat-intel text.

    Writes a one-row CSV compatible with the same schema first_present() expects
    elsewhere in this codebase (consolidate_findings.py / agent_batch_processor.py
    look for columns named IP/Hostname/Finding/Severity among their candidate
    lists), so freeform-pasted text can flow through the same downstream
    pipeline as a spreadsheet-derived row.
    """
    MAX_FINDING_CHARS = 500

    stripped = text.strip() if text else ""
    finding_text = stripped if len(stripped) <= MAX_FINDING_CHARS else stripped[:MAX_FINDING_CHARS]

    row_data = {
        "_sheet": "pasted",
        "IP": "N/A",
        "Hostname": "N/A",
        "Finding": finding_text,
        "Severity": "Unknown",
    }

    flattened_df = pd.DataFrame([row_data])
    flattened_df.to_csv(output_csv, index=False)
    print(f"Saved pasted text as a single-row assessment to {output_csv}.")
    return flattened_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and optionally embed assessment reports (Excel/CSV)")
    parser.add_argument("filepath", help="Path to the .xlsx or .csv file")
    args = parser.parse_args()

    ingest_file(args.filepath)
````

---

## FILE: `agent_batch_processor.py` (sha256=03862d6b9ce4518adc81b2c7e53c428e188a4d45fc9aeb734d95798e3a52ace5)

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

        zig_activities_direct = []
        cref_approaches = []
        cref_mitigations = []

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

            # Direct ZIG-activity / CREF-approach / CREF-mitigation edges that target
            # this technique (relationship_type 'mitigates' / 'mitigates_architecturally').
            for edge in mitre_subgraph.get('edges', []):
                if edge.get('target') != mitre_node_id:
                    continue
                src_data = mitre_subgraph['nodes'].get(edge['source'], {})
                src_type = src_data.get('type')
                if src_type == 'zig_activity' and edge.get('relationship') == 'mitigates':
                    zig_activities_direct.append((edge['source'], src_data))
                elif src_type == 'cref_approach' and edge.get('relationship') == 'mitigates_architecturally':
                    cref_approaches.append((edge['source'], src_data))
                elif src_type == 'cref_mitigation' and edge.get('relationship') == 'mitigates':
                    cref_mitigations.append((edge['source'], src_data))

        d3fend_cm_1 = d3fend_countermeasures[0] if len(d3fend_countermeasures) > 0 else "None found in graph"
        d3fend_cm_2 = d3fend_countermeasures[1] if len(d3fend_countermeasures) > 1 else "None found in graph"
        d3fend_art_str = ", ".join(d3fend_artifacts[:3]) if d3fend_artifacts else "None found in graph"
        mitre_analytics_str = ("\n  - " + "\n  - ".join(analytics[:2])) if analytics else "None specified"
        mitre_mitigations_str = ("\n  - " + "\n  - ".join(mitigations[:2])) if mitigations else "None specified"

        # 3. Zero Trust (ZIG) Correlation
        # Prefer the direct zig_activity -> attack_technique edge (sourced from the
        # DoD Zero Trust Strategy activity-level crosswalk) over keyword matching.
        zig_activity_id = zig_cap_id = "None found"
        zig_activity_name = zig_cap_name = "No matching ZIG activity"
        zig_techs = []

        if zig_activities_direct:
            zig_activity_id, zig_activity_data = zig_activities_direct[0]
            zig_activity_name = zig_activity_data.get('name', zig_activity_id)
            for u, v, data in engine.graph.out_edges(zig_activity_id, data=True):
                if data.get('relationship') == 'belongs_to_capability':
                    cap_node = engine.query_node(v)
                    zig_cap_id, zig_cap_name = v, (cap_node.get('name', v) if cap_node else v)
                    break
        else:
            # Fallback: the ZT crosswalk doesn't cover every technique yet. Rank ZIG
            # nodes against the top countermeasure NAME (not its "[ID] Name" string).
            search_term = d3fend_countermeasures[0].split('] ', 1)[-1] if d3fend_countermeasures else "Access Control"
            zig_ranked = engine.keyword_rank(search_term, top_k=100)
            zig_caps = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_capability']
            zig_techs = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_technology']

            if not zig_caps:
                fallback_ranked = engine.keyword_rank("access management authentication", top_k=100)
                zig_caps = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_capability']
                if not zig_techs:
                    zig_techs = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_technology']

            if zig_caps:
                zig_cap_id, zig_cap_name = zig_caps[0][0], zig_caps[0][1].get('name', 'Unknown')

        # Resolve the capability's pillar from the graph instead of hardcoding it
        zig_pillar = "Unknown Pillar"
        if zig_cap_id != "None found":
            for u, v, data in engine.graph.out_edges(zig_cap_id, data=True):
                if data.get('relationship') == 'belongs_to_pillar':
                    pillar_node = engine.query_node(v)
                    zig_pillar = pillar_node.get('name', v) if pillar_node else v
                    break

        # 4. CREF Architectural Resiliency: walk the first approach up
        # Approach -> Technique -> Objective -> Goal, plus its Effect.
        cref_goal = cref_objective = cref_technique_name = cref_approach_name = cref_effect = "None found in graph"
        cref_approach_id = "None"
        cref_technique_id_found = None
        if cref_approaches:
            cref_approach_id, cref_approach_data = cref_approaches[0]
            cref_approach_name = cref_approach_data.get('name', cref_approach_id)
            for u, v, data in engine.graph.out_edges(cref_approach_id, data=True):
                rel = data.get('relationship')
                if rel == 'realizes_technique':
                    cref_technique_id_found = v
                    tech_node = engine.query_node(v)
                    cref_technique_name = tech_node.get('name', v) if tech_node else v
                elif rel == 'has_effect':
                    eff_node = engine.query_node(v)
                    cref_effect = eff_node.get('name', v) if eff_node else v
            if cref_technique_id_found:
                for u, v, data in engine.graph.out_edges(cref_technique_id_found, data=True):
                    rel = data.get('relationship')
                    if rel == 'achieves_objective':
                        obj_node = engine.query_node(v)
                        cref_objective = obj_node.get('name', v) if obj_node else v
                        for _, gv, gdata in engine.graph.out_edges(v, data=True):
                            if gdata.get('relationship') == 'serves_goal':
                                goal_node = engine.query_node(gv)
                                cref_goal = goal_node.get('name', gv) if goal_node else gv
                                break

        cref_recommendation = (
            f"Because {mitre_name} can recur in forms tactical controls won't catch, "
            f"engineer for {cref_approach_name.lower()} ({cref_goal.lower()} the mission) "
            f"rather than relying solely on the Section 2-3 tactical blockers."
            if cref_approaches else
            "No CREF architectural approach mapped to this technique in the graph; "
            "tactical controls (Sections 2-3) are the primary mitigation for this finding."
        )

        # 5. NIST SP 800-53 Compliance Mapping, from the first cref_mitigation found.
        cref_mitigation_id = "None found in graph"
        cref_mitigation_name = "No matching CREF/ATT&CK mitigation with a control mapping"
        nist_controls = []
        zig_activity_id_from_mitigation = None
        if cref_mitigations:
            cref_mitigation_id, cm_data = cref_mitigations[0]
            cref_mitigation_name = cm_data.get('name', cref_mitigation_id)
            for u, v, data in engine.graph.out_edges(cref_mitigation_id, data=True):
                rel = data.get('relationship')
                if rel == 'satisfies_control':
                    nist_controls.append(v)
                elif rel == 'implements_activity':
                    zig_activity_id_from_mitigation = v
        nist_controls_str = ", ".join(nist_controls) if nist_controls else "None mapped in graph"
        traceability = (
            f"Implements CREF Approach {cref_approach_id} / ZIG Activity {zig_activity_id_from_mitigation or zig_activity_id}"
            if cref_mitigations else
            "N/A — no CREF/ATT&CK mitigation mapped to this technique"
        )

        # 6. Cyber Survivability Attribute (CSA) impact, from the resolved CREF technique.
        csa_name = "None found in graph"
        csa_impact_summary = "No DoD Cyber Survivability Attribute mapped to this technique in the graph."
        if cref_technique_id_found:
            for u, v, data in engine.graph.in_edges(cref_technique_id_found, data=True):
                if data.get('relationship') == 'associated_with_technique':
                    csa_node = engine.query_node(u)
                    if csa_node:
                        csa_name = csa_node.get('name', u)
                        csa_impact_summary = f"This finding threatens the ability to {csa_name.lower()}."
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
            CSA_NAME=csa_name,
            CSA_IMPACT_SUMMARY=csa_impact_summary,
            ZIG_PILLAR_NAME=zig_pillar,
            ZIG_CAPABILITY_ID=zig_cap_id,
            ZIG_CAPABILITY_NAME=zig_cap_name,
            ZIG_ACTIVITY_1=f"[{zig_activity_id}] {zig_activity_name}" if zig_activities_direct else "Identify and remediate vulnerable configurations",
            ZIG_TECHNOLOGY_1=f"[{zig_techs[0][0]}] {zig_techs[0][1].get('name')}" if len(zig_techs) > 0 else "None found in graph",
            ZIG_TECHNOLOGY_2=f"[{zig_techs[1][0]}] {zig_techs[1][1].get('name')}" if len(zig_techs) > 1 else "None found in graph",
            CREF_GOAL=cref_goal,
            CREF_OBJECTIVE=cref_objective,
            CREF_TECHNIQUE=cref_technique_name,
            CREF_APPROACH=cref_approach_name,
            CREF_APPROACH_ID=cref_approach_id,
            CREF_EFFECT=cref_effect,
            CREF_RECOMMENDATION=cref_recommendation,
            CREF_MITIGATION_ID=cref_mitigation_id,
            CREF_MITIGATION_NAME=cref_mitigation_name,
            NIST_800_53_CONTROLS=nist_controls_str,
            TRACEABILITY=traceability,
            TECHNOLOGY_IMPLEMENTATION_NOTES="Ensure configurations align with vendor security baselines.",
            IMMEDIATE_ACTION=imm_action,
            SHORT_TERM_ACTION="Implement continuous monitoring for this vulnerability class.",
            LONG_TERM_ACTION=f"Integrate {zig_cap_name} architecture fully; adopt {cref_approach_name} per Section 4." if cref_approaches else f"Integrate {zig_cap_name} architecture fully."
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

## FILE: `agent_crawl_example.py` (sha256=d3a08b5e7f4b38fe9566a13bcb598e8eb225d02b15e79fd58e4ddad6a2c3a4ee)

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
        
    print("\n[Agent] Checking the same MITRE subgraph for direct CREF/ZIG-activity/NIST edges...")
    # These are the new edges added by consolidate_cref_data.py: a zig_activity or
    # cref_approach can point straight at the ATT&CK technique with 'mitigates' /
    # 'mitigates_architecturally', no keyword matching required.
    if mitre_results:
        for edge in mitre_subgraph.get('edges', []):
            if edge['target'] != mitre_node_id:
                continue
            src_data = mitre_subgraph['nodes'].get(edge['source'], {})
            src_type = src_data.get('type')
            if src_type == 'zig_activity':
                print(f"  - Direct ZIG Activity: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
            elif src_type == 'cref_approach':
                print(f"  - CREF Approach: [{edge['source']}] {src_data.get('name')} --mitigates_architecturally--> {mitre_node_id}")
            elif src_type == 'cref_mitigation':
                print(f"  - CREF/NIST Mitigation: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
                for _, v, data in engine.graph.out_edges(edge['source'], data=True):
                    if data.get('relationship') == 'satisfies_control':
                        control_node = engine.query_node(v)
                        print(f"      satisfies_control --> [{v}] (NIST SP 800-53)")

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

## 4. Long-Term Architectural Resiliency (CREF)

### Resiliency Chain
- **Goal:** Withstand
- **Objective:** Limit Damage
- **Technique:** Privilege Restriction
- **Approach:** Attribute-Based Usage Restriction
- **Effect:** Limit

### Architectural Recommendation
Because forged tickets bypass password-based tactical controls entirely, engineer for
attribute-based usage restriction (limit the mission's blast radius) rather than relying
solely on credential rotation.

---

## 5. NIST SP 800-53 Compliance Mapping

- **Mitigation:** CM1164 - Calibrate Administrative Access
- **Satisfies Control(s):** AC-6(1), AC-6(5)
- **Traceability:** Implements CREF Approach a33 / ZIG Activity 1.2.1

---

## 6. Technology Recommendations

- **Recommended Technologies:**
  - ZIG-TECH-54 - Identity Governance and Administration (IGA)
  - ZIG-TECH-101 - Single Sign-On (SSO) and Federation
- **Implementation Notes:** Ensure IdP is configured to enforce MFA and rotate credentials automatically on a fixed cadence.

---

## 7. Plan of Action and Milestones (POA&M)

- [ ] **Phase 1 (Immediate):** Identify and rotate all potentially compromised service account passwords (krbtgt).
- [ ] **Phase 2 (Short-Term):** Deploy robust Identity Governance and Administration (IGA) tools for continuous monitoring.
- [ ] **Phase 3 (Long-Term/Strategic):** Fully integrate Identity Federation across all enclaves per ZIG Capability 1.5.
"""
    print(assessment_md)
````

---

## FILE: `assessment_template.md` (sha256=f237e6ce6afe37bace7d343d4008311d7901a52e8d496cebec96663d20299165)

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
- **Mission-Level Attribute at Risk (CSA):** {CSA_NAME} — {CSA_IMPACT_SUMMARY}

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

## 4. Long-Term Architectural Resiliency (CREF)

*NIST SP 800-160 Vol. 2 Cyber Resiliency approaches that engineer around this class of threat rather than just blocking today's instance of it — what to build for tomorrow, not what to patch today.*

### Resiliency Chain
- **Goal:** {CREF_GOAL}
- **Objective:** {CREF_OBJECTIVE}
- **Technique:** {CREF_TECHNIQUE}
- **Approach:** {CREF_APPROACH}
- **Effect:** {CREF_EFFECT}

### Architectural Recommendation
*What to engineer, in plain terms, and why tactical controls (Sections 2-3) alone are insufficient here.*
{CREF_RECOMMENDATION}

---

## 5. NIST SP 800-53 Compliance Mapping

*Concrete controls a compliance reviewer can cite. Only list controls actually returned by the graph — state plainly if none exist for this finding.*

- **Mitigation:** {CREF_MITIGATION_ID} - {CREF_MITIGATION_NAME}
- **Satisfies Control(s):** {NIST_800_53_CONTROLS}
- **Traceability:** {TRACEABILITY}

---

## 6. Technology Recommendations

*Specific hardware, software, or configuration classes required to implement the ZIG capabilities and D3FEND countermeasures.*

- **Recommended Technologies:**
  - {ZIG_TECHNOLOGY_1}
  - {ZIG_TECHNOLOGY_2}
- **Implementation Notes:** {TECHNOLOGY_IMPLEMENTATION_NOTES}

---

## 7. Plan of Action and Milestones (POA&M)

*Actionable steps for the engineering and security teams to resolve the gap.*

- [ ] **Phase 1 (Immediate):** {IMMEDIATE_ACTION}
- [ ] **Phase 2 (Short-Term):** {SHORT_TERM_ACTION}
- [ ] **Phase 3 (Long-Term/Strategic):** {LONG_TERM_ACTION}
````

---

## FILE: `threat_assessment_skill.md` (sha256=5be4cf80948c153b7cd0f15c7f9ee4fe0bec45c79aca57c0efe712689776d186)

````markdown
---
name: Generate Zero Trust Threat Assessment
description: Analyzes unstructured threat intelligence or blue team reports, queries the MITRE/D3FEND/ZIG/CREF Knowledge Graph, and generates a structured Plan of Action (POA&M) mitigation report spanning tactical, architectural, and compliance layers.
---

# Generate Zero Trust Threat Assessment

You are an expert Cybersecurity AI Agent. Your objective is to ingest unstructured threat intelligence or network assessment data, translate it into standard MITRE, NSA Zero Trust, and NIST cyber-resiliency frameworks, and output a highly structured remediation plan.

To accomplish this, you must use the Python `KnowledgeGraphEngine` provided in the `scripts/graph_engine.py` file. Note: `semantic_search()` always returns `(node_id, node_data, score)` 3-tuples — in semantic mode AND in the air-gapped keyword-fallback mode. A `[Warning] Semantic search unavailable...` message means the fallback is active; that is normal, not an error.

> **CRITICAL INSTRUCTION: NARROW SCOPE**
> Do not generate a single, massive, monolithic report for a large dataset. You must generate a **series of individual, narrowly focused Action Plans**. Each output report should cover only a single finding (or a very small handful of closely related correlations).

> **CRITICAL INSTRUCTION: FORMATTING**
> Do NOT use emojis in your output. Ensure that the primary MITRE mapping is ALWAYS an ATT&CK Technique (T-code), supplemented by Analytics and Mitigations.

> **CRITICAL INSTRUCTION: EVERY REPORT GETS THE FULL STACK**
> Unlike a purely tactical playbook, every report produced by this skill MUST include the tactical (D3FEND/ZIG), architectural (CREF), and compliance (NIST SP 800-53 / Cyber Survivability Attribute) sections — there is no severity gate. Routine findings still get architectural and compliance context; do not skip Steps 5–7 for "small" findings.

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
The graph now carries a **direct edge** from DoD Zero Trust Activities to the ATT&CK techniques they mitigate (`zig_activity --mitigates--> T-code`), sourced from the DoD Zero Trust Strategy activity-level crosswalk. Prefer this over keyword matching:

1. From the Step 3 subgraph's `edges`, find any edge with `relationship == 'mitigates'` whose target is your T-code and whose source is a `zig_activity` node (check the node's `type` in the subgraph's `nodes`).
2. For each `zig_activity` found, resolve its pillar/capability context: `engine.get_neighbors(zig_activity_id, direction='out')`, filter for the `belongs_to_capability` edge to get the `zig_capability`, then repeat on that capability for the `belongs_to_pillar` edge to get the `zig_pillar`.
3. **Fallback (only if no `zig_activity` was found in step 1):** the ZT crosswalk does not cover every technique yet. Fall back to the legacy correlation: `engine.keyword_rank(countermeasure_name, top_k=100)` using a D3FEND countermeasure's plain name (e.g., "Credential Rotation" — never the "[D3-CRO] Credential Rotation" formatted string) from Step 3, then filter results for `type == 'zig_capability'` and `type == 'zig_technology'`. Resolve the pillar the same way via `belongs_to_pillar`.
4. Optionally crawl the resolved capability (`engine.crawl_subgraph(zig_cap_id, depth=2)`) for its other activities and implementing technologies (`zig_technology`, edge `implements_capability`).

### Step 5: CREF Architectural Resiliency
The graph also carries **strategic mitigations** from NIST SP 800-160 Vol. 2's Cyber Resiliency Engineering Framework (CREF), which cover systems-engineering and recovery-oriented controls that D3FEND/ZIG do not (physical redundancy, non-persistence, diversity, deception).

1. From the Step 3 subgraph, find any `cref_approach` node with a `mitigates_architecturally` edge targeting your T-code.
2. For each `cref_approach` found, walk it up the CREF hierarchy for full context: `engine.get_neighbors(approach_id, direction='out')` → `realizes_technique` edge → `cref_technique` → `achieves_objective` edge → `cref_objective` → `serves_goal` edge → `cref_goal` (one of: Anticipate, Withstand, Recover, Adapt).
3. Also collect the approach's `has_effect` edge → `cref_effect` (e.g., Contain, Preclude, Recover) — this is the plain-English "what this buys you" framing.
4. Report the full chain (Goal → Objective → Technique → Approach → Effect), not just the approach name — the goal/objective context is what makes this section read as architecture rather than a checklist item.

### Step 6: NIST SP 800-53 Compliance Mapping
1. From the Step 3 subgraph, find any `cref_mitigation` node (ID format `CM####`, or occasionally a native `M####` ATT&CK mitigation reused as a CREF mitigation) with a `mitigates` edge targeting your T-code.
2. For each one, call `engine.get_neighbors(cm_id, direction='out')` and collect:
   - `satisfies_control` edges → `nist_800_53_control` nodes (e.g. `AC-4(3)`, `IR-4(2)`) — cite these verbatim for compliance officers.
   - `implements_approach` edges → the `cref_approach` it operationalizes (ties Step 6 back to Step 5).
   - `implements_activity` edges → the `zig_activity` it operationalizes (ties Step 6 back to Step 4).
3. Not every mitigation has a control mapping — if none exists, state that plainly rather than inventing one.

### Step 7: Cyber Survivability Attribute (CSA) Impact
This is the leadership-facing "why the program office should care" framing, from the DoD Cyber Survivability Endorsement catalog.

1. Take the `cref_technique` node(s) resolved in Step 5.
2. Call `engine.get_neighbors(technique_id, direction='in')` and filter for edges with `relationship == 'associated_with_technique'` whose source is a `csa` node (IDs like `CSA-01`).
3. Report the CSA `name` (e.g., "Control Access", "Recover System Capabilities") as the mission-level attribute this finding threatens — this is the sentence a program manager reads, not an engineer.

### Step 8: Assessment Generation
Compile everything gathered in Steps 2–7.
Format your final output strictly according to the structure defined in `assessment_template.md`, filling EVERY placeholder.
Pay special attention to the **"So What?"** section:
1. Executive Summary (Must include the Threat Actor Exploitation & Impact, and the CSA framing from Step 7)
2. MITRE Framework Analysis
3. NSA ZIG Alignment
4. Long-Term Architectural Resiliency (CREF)
5. NIST SP 800-53 Compliance Mapping
6. Technology Recommendations
7. Plan of Action and Milestones (POA&M)

You write the Exploitation Scenario, Business Impact, and POA&M actions yourself from the finding's context — but **never invent MITRE techniques, D3FEND countermeasures, ZIG capabilities, CREF approaches, NIST controls, or CSA IDs. Always pull framework identifiers directly from the `KnowledgeGraphEngine` outputs.**

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

## FILE: `consolidate_cref_data.py` (sha256=2641d658cd3ec44e682fd51cd4761c63b1ad0d3e8f92807c76144ff028ee2bfd)

````python
"""Regenerates cref_nodes.csv / cref_edges.csv from the raw CREF/*.csv files, and
reconciles the DoD Zero Trust Strategy Pillar/Capability/Activity taxonomy found in
CREF/zero-trust-attack.csv against the EXISTING zig_nodes.csv/zig_edges.csv.

Why a separate reconciliation step: CREF/zero-trust-attack.csv encodes the same 7 DoD
Zero Trust pillars (User, Device, Network & Environment, Application & Workload, Data,
Automation & Orchestration, Visibility & Analytics) that scripts/parse_zig_data.py
already extracted from the NSA ZIG PDFs as ZIG-PIL-*/ZIG-CAP-*/ZIG-ACT-* nodes. Treating
it as a fresh taxonomy would duplicate every pillar/capability/activity. Instead this
script:
  - reuses the existing ZIG-PIL-{n} / ZIG-CAP-{id} / ZIG-ACT-{id} node IDs verbatim
  - ADDS the ~3 capabilities and ~59 activities present in the new dataset but missing
    from the PDF extraction
  - OVERWRITES existing zig_activity name/description with the new dataset's clean text
    (the PDF extraction is dot-leader/pagination garbage, e.g. "Inventory User ... D-";
    zero-trust-attack.csv's activity_name/activity_description is the authoritative
    source of truth for this layer)
  - never touches zig_pillar or existing zig_capability names (those extracted fine)

New node types this script introduces (none of these previously existed in the graph):
  cref_goal, cref_objective, cref_technique, cref_approach,
  cref_design_principle_strategic, cref_design_principle_structural,
  csa (DoD Cyber Survivability Attribute), cref_effect,
  cref_mitigation (CM#### catalog), nist_800_53_control

Source files (NIST SP 800-160 Vol 2 Cyber Resiliency Engineering Framework, the DoD
Cyber Survivability Endorsement Implementation Guide, and the DoD Zero Trust Strategy
activity-level crosswalk):
  CREF/cref-relationships.csv          Goal -> Objective -> Technique -> Approach (canonical taxonomy)
  CREF/design-principles-cref.csv      Strategic/Structural Design Principle -> Technique
  CREF/csa-cref-attack.csv             CSA -> Design Principles -> Technique/Approach -> ATT&CK
  CREF/impact.csv                      Technique/Approach -> Effect
  CREF/attack-relationships-sankey-export.csv   Approach -> ATT&CK -> CM Mitigation -> NIST 800-53 Control
  CREF/zero-trust-attack.csv           ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation

Run after ANY change to the CREF/ raw files:
    python3 consolidate_cref_data.py
"""
import csv
import os
import re

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREF_DIR = os.path.join(BASE_DIR, "CREF")

# ---------------------------------------------------------------------------
# New CREF/CSA/NIST-control nodes + edges (written to cref_nodes.csv / cref_edges.csv)
# ---------------------------------------------------------------------------
cref_nodes = {}   # id -> {id, type, name, description, url}
cref_edges = set()  # (source_id, target_id, relationship_type)


def cref_id(prefix, raw):
    """Turns a raw CREF id ('g1', 'sta4', 'a45') into a globally unique node id."""
    digits = re.sub(r"[^0-9.]", "", str(raw))
    return f"{prefix}-{digits}"


def add_cref_node(id_, type_, name, description=""):
    if pd.isna(id_) or not str(id_).strip():
        return None
    id_ = str(id_).strip()
    if id_ not in cref_nodes:
        cref_nodes[id_] = {
            "id": id_,
            "type": type_,
            "name": str(name).strip() if pd.notna(name) else "",
            "description": str(description).strip() if pd.notna(description) else "",
            "url": "",
        }
    elif not cref_nodes[id_]["description"] and pd.notna(description) and str(description).strip():
        cref_nodes[id_]["description"] = str(description).strip()
    return id_


def add_cref_edge(source_id, target_id, rel_type):
    if pd.isna(source_id) or pd.isna(target_id):
        return
    source_id, target_id = str(source_id).strip(), str(target_id).strip()
    if not source_id or not target_id:
        return
    cref_edges.add((source_id, target_id, rel_type))


def read_csv(name):
    return pd.read_csv(os.path.join(CREF_DIR, name))


# Some rows use a native ATT&CK Mitigation ID (e.g. "M1026") in the mitigation_id
# column instead of the DoD CM#### catalog. Those nodes already exist in
# mitre_nodes.csv as type attack_mitigation -- writing them into cref_nodes.csv as
# type cref_mitigation would silently overwrite the correct type when the graph
# loads mitre_nodes.csv then cref_nodes.csv. Detect and skip node creation for them
# (edges to/from them still get added normally).
print("Loading mitre_nodes.csv IDs (native-mitigation collision check)...")
with open(os.path.join(BASE_DIR, "mitre_nodes.csv"), encoding="utf-8") as f:
    mitre_ids = {row["id"] for row in csv.DictReader(f)}


def add_mitigation_node(raw_id, name):
    mid = str(raw_id).strip() if pd.notna(raw_id) else ""
    if not mid:
        return None
    if mid in mitre_ids:
        return mid
    return add_cref_node(mid, "cref_mitigation", name)


print("Parsing cref-relationships.csv (canonical Goal->Objective->Technique->Approach)...")
df = read_csv("cref-relationships.csv")
for _, row in df.iterrows():
    g = add_cref_node(cref_id("CREF-GOAL", row["goal_id"]), "cref_goal", row["Goal"], row.get("goal_description"))
    o = add_cref_node(cref_id("CREF-OBJ", row["obj_id"]), "cref_objective", row["Objective"], row.get("obj_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["Technique"], row.get("tech_description"))
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["Approach"], row.get("app_description"))
    if g and o:
        add_cref_edge(o, g, "serves_goal")
    if o and t:
        add_cref_edge(t, o, "achieves_objective")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")

print("Parsing design-principles-cref.csv...")
df = read_csv("design-principles-cref.csv")
for _, row in df.iterrows():
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    rel = "requires_principle" if pd.notna(row.get("required")) and int(row["required"]) == 1 else "informs_principle"
    if t and sta:
        add_cref_edge(t, sta, rel)
    if t and stu:
        add_cref_edge(t, stu, rel)

print("Parsing csa-cref-attack.csv (DoD Cyber Survivability Attributes)...")
df = read_csv("csa-cref-attack.csv")
for _, row in df.iterrows():
    csa = add_cref_node(str(row["csa_id"]).strip(), "csa", row["csa_name"])
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["APPROACH_ID"]), "cref_approach", row["approach"])
    if csa and sta:
        add_cref_edge(csa, sta, "embodies_principle")
    if csa and stu:
        add_cref_edge(csa, stu, "embodies_principle")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if csa and t:
        add_cref_edge(csa, t, "associated_with_technique")
    if a and pd.notna(row.get("attack_technique_id")):
        add_cref_edge(a, str(row["attack_technique_id"]).strip(), "mitigates_architecturally")

print("Parsing impact.csv (Approach -> Effect)...")
df = read_csv("impact.csv")
for _, row in df.iterrows():
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["approach_id"]), "cref_approach", row["approach"])
    e = add_cref_node(cref_id("CREF-EFFECT", row["effect_id"]), "cref_effect", row["effect"])
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if a and e:
        add_cref_edge(a, e, "has_effect")

print("Parsing attack-relationships-sankey-export.csv (Approach -> ATT&CK -> CM Mitigation -> NIST 800-53)...")
df = read_csv("attack-relationships-sankey-export.csv")
for _, row in df.iterrows():
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["approach"], row.get("app_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["technique"], row.get("tech_description"))
    if a and t:
        add_cref_edge(a, t, "realizes_technique")

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and pd.notna(row.get("control")):
            control = add_cref_node(str(row["control"]).strip(), "nist_800_53_control", row["control"])
            if cm and control:
                add_cref_edge(cm, control, "satisfies_control")

# ---------------------------------------------------------------------------
# zero-trust-attack.csv: reconcile against existing ZIG nodes, then add the new
# cref_mitigation/cref_approach edges plus the direct ZIG-activity<->ATT&CK bridge.
# ---------------------------------------------------------------------------
print("Loading existing zig_nodes.csv / zig_edges.csv for reconciliation...")
zig_nodes = {}
with open(os.path.join(BASE_DIR, "zig_nodes.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_nodes[row["id"]] = dict(row)

zig_edges = set()
with open(os.path.join(BASE_DIR, "zig_edges.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_edges.add((row["source_id"], row["target_id"], row["relationship_type"]))

new_zig_activities = new_zig_capabilities = 0

print("Parsing zero-trust-attack.csv (ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation)...")
df = read_csv("zero-trust-attack.csv")
for _, row in df.iterrows():
    pillar_id = str(row["pillar_id"]).strip() if pd.notna(row.get("pillar_id")) else None
    cap_id = str(row["capability_id"]).strip() if pd.notna(row.get("capability_id")) else None
    act_id = str(row["activity_id"]).strip() if pd.notna(row.get("activity_id")) else None

    zig_pil = f"ZIG-PIL-{pillar_id}" if pillar_id else None
    zig_cap = f"ZIG-CAP-{cap_id}" if cap_id else None
    zig_act = f"ZIG-ACT-{act_id}" if act_id else None

    # Add capabilities missing from the PDF extraction (never overwrite existing ones).
    if zig_cap and zig_cap not in zig_nodes:
        zig_nodes[zig_cap] = {"id": zig_cap, "type": "zig_capability",
                               "name": str(row["capability_name"]).strip(), "description": "", "url": ""}
        new_zig_capabilities += 1
        if zig_pil:
            zig_edges.add((zig_cap, zig_pil, "belongs_to_pillar"))

    # Activities: add if missing, or overwrite the PDF-scraped garbage name/description
    # with this dataset's clean text (authoritative source for this layer).
    if zig_act:
        clean_name = str(row["activity_name"]).strip() if pd.notna(row.get("activity_name")) else ""
        clean_desc = str(row["activity_description"]).strip() if pd.notna(row.get("activity_description")) else ""
        if zig_act not in zig_nodes:
            zig_nodes[zig_act] = {"id": zig_act, "type": "zig_activity",
                                   "name": clean_name, "description": clean_desc, "url": ""}
            new_zig_activities += 1
            if zig_cap:
                zig_edges.add((zig_act, zig_cap, "belongs_to_capability"))
        elif clean_name:
            zig_nodes[zig_act]["name"] = clean_name
            zig_nodes[zig_act]["description"] = clean_desc

    a = add_cref_node(cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("approach")) \
        if pd.notna(row.get("app_id")) else None

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    # The direct ZIG-activity <-> ATT&CK bridge: previously this correlation only
    # existed via fuzzy keyword matching of D3FEND countermeasure names (see
    # threat_assessment_skill.md Step 4). This is a precise graph edge instead.
    if zig_act and attack_id:
        cref_edges.add((zig_act, attack_id, "mitigates"))

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and zig_act:
            add_cref_edge(cm, zig_act, "implements_activity")

print(f"  Added {new_zig_capabilities} new zig_capability nodes, {new_zig_activities} new zig_activity nodes.")
print(f"  Cleaned activity names/descriptions for {len(df['activity_id'].dropna().astype(str).str.strip().unique()) - new_zig_activities} existing zig_activity nodes.")

# ---------------------------------------------------------------------------
# Integrity pass: drop cref_edges whose endpoint is not a real node anywhere in
# the graph (mitre_nodes.csv, the now-reconciled zig_nodes, or our own new nodes).
# Mirrors the same pass in consolidate_mitre_data.py.
# ---------------------------------------------------------------------------
known_ids = set(cref_nodes.keys()) | set(zig_nodes.keys()) | mitre_ids
before = len(cref_edges)
cref_edges = {e for e in cref_edges if e[0] in known_ids and e[1] in known_ids}
dropped = before - len(cref_edges)
if dropped:
    print(f"Integrity pass: dropped {dropped} edges referencing unknown node IDs ({len(cref_edges)} remain).")

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
print("Writing cref_nodes.csv / cref_edges.csv...")
pd.DataFrame(list(cref_nodes.values())).to_csv(os.path.join(BASE_DIR, "cref_nodes.csv"), index=False)
pd.DataFrame(list(cref_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "cref_edges.csv"), index=False)

print("Writing reconciled zig_nodes.csv / zig_edges.csv...")
pd.DataFrame(list(zig_nodes.values())).to_csv(os.path.join(BASE_DIR, "zig_nodes.csv"), index=False)
pd.DataFrame(list(zig_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "zig_edges.csv"), index=False)

print(f"Done! CREF: {len(cref_nodes)} nodes, {len(cref_edges)} edges. "
      f"ZIG (reconciled): {len(zig_nodes)} nodes, {len(zig_edges)} edges.")
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

## FILE: `build_deployment_guide.py` (sha256=639688581709d122fb3b7beaccbe562770e518d58dfb40eacef64425c51fe805)

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
# source files (ATT&CK xlsx, D3FEND csv, ZIG PDFs, CREF/*.csv) were ported instead.
# Order matters: consolidate_cref_data.py reads mitre_nodes.csv and zig_nodes.csv to
# validate/reconcile against, so it must run AFTER the other two.
REGEN_FILES = [
    ("consolidate_mitre_data.py", "python"),
    ("scripts/parse_zig_data.py", "python"),
    ("consolidate_cref_data.py", "python"),
]


def count_csv(path):
    with open(os.path.join(BASE_DIR, path), encoding="utf-8") as f:
        return sum(1 for _ in csv.DictReader(f))


def graph_counts():
    """Deduplicated counts as the engine will actually report them."""
    import networkx as nx
    g = nx.DiGraph()
    for nodes_file, edges_file in [("mitre_nodes.csv", "mitre_edges.csv"),
                                   ("zig_nodes.csv", "zig_edges.csv"),
                                   ("cref_nodes.csv", "cref_edges.csv")]:
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
    cref_nodes = count_csv("cref_nodes.csv")
    cref_edges = count_csv("cref_edges.csv")
    total_nodes, total_edges = graph_counts()

    code_sections = "\n---\n\n".join(embed(p, lang) for p, lang in EMBEDDED_FILES)
    regen_sections = "\n---\n\n".join(embed(p, lang) for p, lang in REGEN_FILES)

    guide = GUIDE_TEMPLATE.format(
        mitre_nodes=mitre_nodes, mitre_edges=mitre_edges,
        zig_nodes=zig_nodes, zig_edges=zig_edges,
        cref_nodes=cref_nodes, cref_edges=cref_edges,
        total_nodes=total_nodes, total_edges=total_edges,
        code_sections=code_sections, regen_sections=regen_sections,
    )

    out = os.path.join(BASE_DIR, "Air_Gapped_Deployment_Guide.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out}")
    print(f"Verification numbers baked in: {total_nodes} nodes / {total_edges} edges "
          f"(MITRE {mitre_nodes}/{mitre_edges}, ZIG {zig_nodes}/{zig_edges}, "
          f"CREF {cref_nodes}/{cref_edges})")


GUIDE_TEMPLATE = '''# Air-Gapped Deployment Guide & Agent Reconstruction Plan

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> Your task is to stand up a Python-based threat-intelligence knowledge graph on this
> air-gapped network. The system maps unstructured red/blue team findings or network
> vulnerability scans to MITRE ATT&CK techniques, D3FEND countermeasures, NSA Zero
> Trust (ZIG) capabilities/activities, NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF)
> approaches, NIST SP 800-53 controls, and DoD Cyber Survivability Attributes, then
> generates standardized POA&M reports spanning tactical, architectural, and
> compliance layers.
>
> **Follow this document top to bottom. Do not improvise, do not "improve" the code,
> and do not skip verification steps.** Every source file you need is embedded below
> in full — copy each one byte-for-byte. After every stage, run the listed
> verification command and compare against the expected output before moving on.
> If a verification fails, stop and fix that stage; later stages depend on it.

---

## 1. What This System Is

Three cooperating pieces, all plain Python:

1. **Knowledge Graph Engine** (`scripts/graph_engine.py`) — loads six CSVs into a
   NetworkX directed graph ({total_nodes} nodes, {total_edges} edges) unifying
   MITRE ATT&CK, MITRE D3FEND, the NSA Zero Trust Implementation Guide (ZIG), and
   NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF) — the last of which also carries
   the DoD Zero Trust Strategy activity-level crosswalk, NIST SP 800-53 control
   citations, and DoD Cyber Survivability Attributes (CSA).
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
| 1 | The six graph CSVs: `mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`, `zig_edges.csv`, `cref_nodes.csv`, `cref_edges.csv` | ~9 MB | The knowledge graph itself. Without these you must regenerate from raw sources (Section 7). |
| 2 | This guide | ~200 KB | Contains every source file in full. |
| 3 | `graph_embeddings.npz` + `embedding_metadata.json` | ~9 MB | Pre-computed node vectors. Saves re-running `embed_graph.py`, but semantic mode still needs item 4 to encode queries. |
| 4 | HuggingFace model cache dir `models--sentence-transformers--all-MiniLM-L6-v2` (from `~/.cache/huggingface/hub/`) | ~90 MB | Required to embed NEW text (queries, new assessments) in semantic mode. |
| 5 | Python wheels: `networkx`, `pandas`, `openpyxl`, `odfpy`; optionally `numpy`, `scikit-learn`, `sentence-transformers` (+torch) | varies | Tier 1–2 are small and mandatory; Tier 3 is ~2 GB with torch and optional. |
| 6 | Raw sources: `enterprise-attack-v19.1(1).xlsx`, `d3fend.csv`, `d3fend-full-mappings.csv`, `ATT&CK_D3FEND_Mappings.ods`, ZIG PDF text extracts, `CREF/*.csv` | ~50 MB | Only needed if item 1 could not be ported. |

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
├── zig_nodes.csv              # ported or generated by scripts/parse_zig_data.py, THEN reconciled by consolidate_cref_data.py
├── zig_edges.csv              # ported or generated
├── cref_nodes.csv             # ported or generated by consolidate_cref_data.py (run LAST — needs mitre_nodes.csv + zig_nodes.csv)
├── cref_edges.csv             # ported or generated
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
ZIG = {zig_nodes} nodes / {zig_edges} edges, CREF = {cref_nodes} nodes / {cref_edges} edges.

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
libraries. Create the three scripts below, then run THEM IN THIS ORDER:

```bash
python3 consolidate_mitre_data.py      # → mitre_nodes.csv, mitre_edges.csv, ontology.json
cd raw_data/zig 2>/dev/null || true    # parse_zig_data.py expects the ZIG .txt files in its cwd
python3 scripts/parse_zig_data.py      # → zig_nodes.csv, zig_edges.csv (move them to repo root)
cd - 2>/dev/null || true
python3 consolidate_cref_data.py       # → cref_nodes.csv, cref_edges.csv; ALSO reconciles zig_nodes.csv/zig_edges.csv
```

Notes for the agent:
- `consolidate_mitre_data.py` ends with an integrity pass that drops edges
  referencing unknown node IDs. A small number of dropped edges (tens, not
  hundreds) is normal.
- The ZIG parser reads text extracted from the NSA ZIG PDFs
  (`CTR_ZIG_*.PDF.txt`) plus `zig_tech_mappings.txt`. If only the PDFs are
  available, extract text first (any PDF-to-text tool; `pdfplumber` works).
- `consolidate_cref_data.py` MUST run last: it reads `mitre_nodes.csv` to validate
  edge targets and to detect the ~28 mitigation IDs that are actually native ATT&CK
  `M####` codes (skip creating a duplicate `cref_mitigation` node for those — the
  existing `attack_mitigation` node is authoritative). It also OVERWRITES
  `zig_nodes.csv`/`zig_edges.csv` in place: it reuses the existing
  `ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*` IDs rather than minting duplicates for the
  same DoD Zero Trust pillars, adds the ~3 capabilities and ~59 activities present
  in `CREF/zero-trust-attack.csv` but missing from the PDF extraction, and replaces
  garbled PDF-extracted `zig_activity` names/descriptions with the clean text from
  that file. Do not re-run `scripts/parse_zig_data.py` after this step — it would
  overwrite the reconciliation with the original PDF-scraped data.
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
| `CREF-GOAL-` / `CREF-OBJ-` / `CREF-TECH-` / `CREF-APP-` | `cref_goal` / `cref_objective` / `cref_technique` / `cref_approach` | NIST SP 800-160 Vol. 2 CREF taxonomy |
| `CREF-STA-` / `CREF-STU-` | `cref_design_principle_strategic` / `cref_design_principle_structural` | CREF design principles |
| `CSA-` | `csa` | DoD Cyber Survivability Attribute |
| `CREF-EFFECT-` | `cref_effect` | CREF effect (Contain, Preclude, Recover, ...) |
| `CM####` (or a native `M####` when reused) | `cref_mitigation` | DoD cyber-resiliency mitigation catalog |
| e.g. `AC-4(3)`, `IR-4(2)` | `nist_800_53_control` | NIST SP 800-53 control |

**Key relationship types:** `belongs_to_tactic`, `subtechnique_of`, `uses`
(group/software/campaign → technique), `mitigates` (M → T), `detects` (DET → T),
`has_analytic` (DET → AN), `monitors_data_component` (AN → DC),
`mapped_to_d3fend_technique` (M → D3-), `targets` (DA → OA), plus D3FEND artifact
verbs (`accesses`, `modifies`, `creates`, ...), and ZIG's `belongs_to_pillar`,
`belongs_to_capability`, `implements_capability` (ZIG-TECH → ZIG-CAP). CREF adds:
`realizes_technique` (Approach → Technique), `achieves_objective` (Technique →
Objective), `serves_goal` (Objective → Goal), `requires_principle`/
`informs_principle` (Technique → Design Principle), `embodies_principle` (CSA →
Design Principle), `associated_with_technique` (CSA → Technique), `has_effect`
(Approach → Effect), `mitigates_architecturally` (Approach → T-code, the
architectural counterpart to native `mitigates`), `implements_approach` (CM → CREF
Approach), `satisfies_control` (CM → NIST control), `implements_activity` (CM →
ZIG Activity), and a **direct** `mitigates` edge from `zig_activity` straight to a
T-code (sourced from the DoD Zero Trust Strategy crosswalk — no keyword matching
required where this edge exists).

**CSV schemas:** node files are `id,type,name,description,url`; edge files are
`source_id,target_id,relationship_type`.

---

## 9. Agent Workflow: From Threat Intel to Remediation Plan

When a user hands you unstructured findings, do this per finding (this is what
`agent_batch_processor.py` automates — read it as the reference implementation):

This applies whether the input is unstructured threat intel text or a flattened
network vulnerability finding (Section 6.3's `ingest_assessment.py` path) — both
go through the same technique-mapping step; only the entity-extraction step differs.

1. **Extract** the core technical behavior from the text (e.g. "forged Kerberos tickets").
2. **Map** it to an ATT&CK technique: `engine.semantic_search(text, top_k=20)`,
   then take the highest-scoring result whose ID starts with `T` followed by a
   digit. Never map the primary finding to an `AN`, `M`, or `DET` node.
3. **Crawl** for defenses: `engine.crawl_subgraph(t_code, depth=2)`. From the
   returned nodes collect `d3fend_technique` (countermeasures),
   `defensive_artifact`/`attack_datacomponent` (artifacts), `attack_analytic`
   (detections — quote their `description`), `attack_mitigation`.
4. **Correlate to Zero Trust:** check the Step 3 subgraph's edges for a
   `zig_activity` with a direct `mitigates` edge to the T-code (from the DoD Zero
   Trust Strategy crosswalk); resolve its capability/pillar via `belongs_to_capability`
   then `belongs_to_pillar`. Only if none exists, fall back to
   `engine.keyword_rank(countermeasure_name, top_k=100)`, filtered for
   `zig_capability`/`zig_technology`.
5. **CREF architectural resiliency:** check the same subgraph for a `cref_approach`
   with a `mitigates_architecturally` edge to the T-code. Walk it up via
   `realizes_technique` → `cref_technique` → `achieves_objective` → `cref_objective`
   → `serves_goal` → `cref_goal`, and sideways via `has_effect` → `cref_effect`.
6. **NIST SP 800-53 compliance:** check the same subgraph for a `cref_mitigation`
   with a `mitigates` edge to the T-code, then follow its `satisfies_control`
   edge(s) to cite concrete controls (e.g. `AC-4(3)`). State plainly if none exist.
7. **Cyber Survivability Attribute framing:** from the `cref_technique` resolved in
   step 5, follow the `associated_with_technique` edge backward to a `csa` node —
   this is the mission-level "why leadership should care" line.
8. **Generate** one narrowly-scoped report per finding by filling EVERY
   placeholder in `assessment_template.md` (all 7 sections — there is no severity
   gate; every report gets the CREF/NIST/CSA layer). Write the Exploitation
   Scenario / Impact / POA&M text yourself from the finding's context. **Never
   invent MITRE, D3FEND, ZIG, CREF, NIST, or CSA identifiers — only use IDs
   returned by the engine.** No emojis in reports.

For bulk processing: `python3 scripts/ingest_assessment.py <report.xlsx>` then
`python3 agent_batch_processor.py --limit N` — then review and enrich the
generated reports (the batch script's Exploitation/Impact text is heuristic;
replace it with your own analysis). `agent_batch_processor.py` is the reference
implementation of steps 2-7 above — read it before writing a from-scratch script.

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
| A `zig_activity` node's `type` attribute got silently changed to `cref_mitigation` (or similar) | Ran `consolidate_cref_data.py` before `mitre_nodes.csv`/`zig_nodes.csv` existed, so its native-ID collision check had nothing to compare against | Re-run in the order given in Section 7: `consolidate_mitre_data.py` → `scripts/parse_zig_data.py` → `consolidate_cref_data.py` |
| ZIG activity names reverted to garbled PDF text (dot-leaders, trailing `D-`) | Ran `scripts/parse_zig_data.py` again after `consolidate_cref_data.py`, overwriting the reconciliation | Re-run `consolidate_cref_data.py` again to re-apply the clean names |
| Section 4/5/7 of a generated report all say "None found in graph" | Normal for techniques the CREF/DoD-ZT-Strategy datasets don't cover yet — not every T-code has an architectural or compliance mapping. Confirm via `engine.crawl_subgraph(t_code, depth=2)` that no `cref_approach`/`cref_mitigation` edges target it | No fix needed; report it as-is rather than inventing a mapping |

---

*This guide is generated by `build_deployment_guide.py` from the live source
files — regenerate it after any code change rather than editing it by hand.*
'''


if __name__ == "__main__":
    main()
````

---

## FILE: `build_cref_extension_guide.py` (sha256=573aa373f5ac3e9742fe3f3ee507dd7a5f8c5dfc8ae154f1d90a9816c44cca08)

````python
"""Generates CREF_ZERO_TRUST_EXTENSION_GUIDE.md — a DELTA guide for an agentic
coding agent that already has the base MITRE/D3FEND/ZIG system (from
Air_Gapped_Deployment_Guide.md or PORTABLE_RECONSTRUCTION_BUNDLE.md) running on an
air-gapped network, and needs to add the CREF/NIST-800-53/DoD-Zero-Trust-Strategy/
Cyber-Survivability-Attribute layer on top of it.

Unlike the full reconstruction guide, this assumes mitre_nodes.csv/mitre_edges.csv
and zig_nodes.csv/zig_edges.csv already exist and the base pipeline already works —
it only covers what changed. Every embedded file is byte-verified with a SHA-256,
same rigor as PORTABLE_RECONSTRUCTION_BUNDLE.md, since this is meant to be applied
on a system you cannot easily SSH into to double-check.

Run after ANY change to the files listed in EMBEDDED_FILES below:
    python3 build_cref_extension_guide.py
"""
import csv
import hashlib
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_NAME = "CREF_ZERO_TRUST_EXTENSION_GUIDE.md"

# Every file this extension touches, new or modified, in the order a coding agent
# should write/overwrite them.
EMBEDDED_FILES = [
    ("consolidate_cref_data.py", "python"),
    ("scripts/graph_engine.py", "python"),
    ("threat_assessment_skill.md", "markdown"),
    ("assessment_template.md", "markdown"),
    ("agent_batch_processor.py", "python"),
    ("agent_crawl_example.py", "python"),
]


def read(relpath):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        return f.read()


def count_csv(path):
    with open(os.path.join(BASE_DIR, path), encoding="utf-8") as f:
        return sum(1 for _ in csv.DictReader(f))


def graph_counts():
    import networkx as nx
    g = nx.DiGraph()
    for nodes_file, edges_file in [("mitre_nodes.csv", "mitre_edges.csv"),
                                   ("zig_nodes.csv", "zig_edges.csv"),
                                   ("cref_nodes.csv", "cref_edges.csv")]:
        with open(os.path.join(BASE_DIR, nodes_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_node(row["id"])
        with open(os.path.join(BASE_DIR, edges_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_edge(row["source_id"], row["target_id"])
    return g.number_of_nodes(), g.number_of_edges()


def fence_for(content):
    """A backtick fence guaranteed longer than any backtick run in content."""
    longest = max((len(r) for r in re.findall(r"`+", content)), default=0)
    return "`" * max(4, longest + 1)


def embed(relpath, lang):
    content = read(relpath)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    fence = fence_for(content)
    block = (f"### FILE: `{relpath}` (sha256={sha})\n\n"
             f"{fence}{lang}\n{content}{fence}\n")
    return block, sha, len(content.encode("utf-8"))


def main():
    cref_nodes = count_csv("cref_nodes.csv")
    cref_edges = count_csv("cref_edges.csv")
    zig_nodes = count_csv("zig_nodes.csv")
    zig_edges = count_csv("zig_edges.csv")
    mitre_nodes = count_csv("mitre_nodes.csv")
    total_nodes, total_edges = graph_counts()

    sections, manifest_rows = [], []
    for relpath, lang in EMBEDDED_FILES:
        block, sha, size = embed(relpath, lang)
        sections.append(block)
        manifest_rows.append(f"| `{relpath}` | {size} | `{sha[:16]}...` |")

    guide = GUIDE_TEMPLATE.format(
        cref_nodes=cref_nodes, cref_edges=cref_edges,
        zig_nodes=zig_nodes, zig_edges=zig_edges, mitre_nodes=mitre_nodes,
        total_nodes=total_nodes, total_edges=total_edges,
        manifest="\n".join(manifest_rows),
        file_sections="\n---\n\n".join(sections),
    )

    out_path = os.path.join(BASE_DIR, OUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out_path}")
    print(f"Verification numbers baked in: CREF {cref_nodes} nodes / {cref_edges} edges, "
          f"reconciled ZIG {zig_nodes} nodes / {zig_edges} edges, "
          f"full graph {total_nodes} nodes / {total_edges} edges")


GUIDE_TEMPLATE = '''# CREF / DoD Zero Trust / NIST 800-53 Extension Guide

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> This is a DELTA guide, not a from-scratch build. It assumes the base MITRE
> ATT&CK/D3FEND/ZIG system from `Air_Gapped_Deployment_Guide.md` (or
> `PORTABLE_RECONSTRUCTION_BUNDLE.md`) is ALREADY deployed and working on this
> network — `mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`, `zig_edges.csv`
> already exist, and `python3 scripts/graph_engine.py` already runs cleanly.
>
> Your task is to add a fourth framework layer — NIST SP 800-160 Vol. 2 Cyber
> Resiliency (CREF), the DoD Zero Trust Strategy activity-level crosswalk, NIST
> SP 800-53 control citations, and DoD Cyber Survivability Attributes (CSA) — on
> top of that system, WITHOUT duplicating anything already in the graph.
>
> **Do STEP 0 before touching any file.** If it fails, stop and fix the base
> system first — this extension cannot be validated on top of a broken base.
> **Follow this document top to bottom. Do not improvise, do not "improve" the
> code, and do not skip verification steps.** Every source file you need is
> embedded below in full, each with a SHA-256 — copy each one byte-for-byte and
> verify the hash before trusting the copy.

---

## STEP 0 — Verify the base system before starting

```bash
python3 scripts/graph_engine.py
```

Expected: a node/edge count with NO `cref_*` or `CSA-*` or `NIST` mentions in the
test output (this extension has not been applied yet), and no traceback. If this
fails, fix the base deployment first (see `Air_Gapped_Deployment_Guide.md` Section 11).

---

## Why this extension exists

The base system covers tactical response: "what technique is this, what D3FEND
countermeasure blocks it, what ZIG capability does that map to." It has two blind
spots this extension fills:

1. **No architectural/resiliency layer.** D3FEND and ZIG are both about blocking or
   detecting a specific technique. Neither covers systems-engineering controls that
   assume the tactical control will eventually fail — redundancy, non-persistence,
   diversity, deception. CREF (NIST SP 800-160 Vol. 2) fills this gap.
2. **No compliance citation.** Leadership and compliance reviewers need a NIST SP
   800-53 control ID and a DoD Cyber Survivability Attribute, not a D3FEND technique
   name. The DoD Zero Trust Strategy crosswalk and the CSA catalog fill this gap, and
   also add a DIRECT edge from ZIG activities to ATT&CK techniques — replacing the
   base system's fuzzy keyword-matching correlation with a precise graph edge for
   every technique this dataset covers.

**Every report this system generates now includes all three layers (tactical,
architectural, compliance) — there is no severity gate.** A routine finding gets the
CREF/NIST/CSA sections too, same as a critical one.

---

## Critical gotcha: do not duplicate the Zero Trust taxonomy

`CREF/zero-trust-attack.csv` encodes the same 7 DoD Zero Trust pillars, ~45
capabilities, and ~140+ activities that `zig_nodes.csv`/`zig_edges.csv` already
carry (extracted from the NSA ZIG PDFs). Naively loading it as a new taxonomy would
create a duplicate `ZT-PIL-*`-style pillar/capability/activity for every one that
already exists as `ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*`.

`consolidate_cref_data.py` handles this correctly by RECONCILING instead of
duplicating:
- reuses the existing `ZIG-PIL-{{n}}` / `ZIG-CAP-{{id}}` / `ZIG-ACT-{{id}}` IDs verbatim
- adds the ~3 capabilities and ~59 activities present in the new dataset but missing
  from the PDF extraction
- OVERWRITES existing `zig_activity` name/description fields with this dataset's
  clean text (the PDF extraction is dot-leader/pagination garbage, e.g.
  `"Inventory User .......... D-"`; the new dataset is authoritative for this layer)
- never touches `zig_pillar` names or existing `zig_capability` names (those
  extracted cleanly the first time)

Do not re-run `scripts/parse_zig_data.py` after applying this extension — it would
overwrite the reconciliation with the original PDF-scraped data. If you ever need to
re-parse the ZIG PDFs from scratch, re-run `consolidate_cref_data.py` again
immediately afterward to re-apply the reconciliation.

A second, subtler gotcha: about 28 rows in the raw CREF files use a native ATT&CK
`M####` mitigation ID in what is otherwise a `CM####`-catalog column. Writing those
into `cref_nodes.csv` as type `cref_mitigation` would silently overwrite their
correct `attack_mitigation` type when the graph loads `cref_nodes.csv` after
`mitre_nodes.csv`. `consolidate_cref_data.py` checks for this (`add_mitigation_node`)
and skips node creation for any ID that already exists in `mitre_nodes.csv`, while
still wiring up the edges. If you hand-modify the script, preserve this check.

---

## Asset Manifest — what to port, in priority order

| Priority | Asset | Why |
|---|---|---|
| 1 | `CREF/` directory: `cref-relationships.csv`, `design-principles-cref.csv`, `csa-cref-attack.csv`, `impact.csv`, `attack-relationships-sankey-export.csv`, `zero-trust-attack.csv` | Raw sources. Plain CSV text — passes a CDS as-is. Required unless you port item 2 instead. |
| 2 | Pre-built `cref_nodes.csv` / `cref_edges.csv` + the RECONCILED `zig_nodes.csv` / `zig_edges.csv` | Skip regeneration entirely if these can be ported directly. Still port item 1 too if you might need to regenerate later (e.g. MITRE/CREF data updates). |
| 3 | This guide | Contains every changed/new source file in full, with hashes. |
| 4 | `graph_embeddings.npz` + `embedding_metadata.json` (regenerated for the new node set) | MANDATORY to re-run `scripts/embed_graph.py` if you did not port these — the node set changed, so the base system's old embeddings are now stale (row count mismatch). |

**Decision tree:**
- Ported item 2? → Skip to STEP 3 (still overwrite the code files in STEP 2 first).
- Only item 1? → Do STEP 1, then STEP 2, then STEP 2.5 regeneration, then STEP 3.

---

## STEP 1 — Back up before mutating ZIG data

`consolidate_cref_data.py` overwrites `zig_nodes.csv`/`zig_edges.csv` in place. Back
them up first so a bad run is a `cp` away from reversible, not a re-parse of the ZIG
PDFs away:

```bash
cp zig_nodes.csv zig_nodes.csv.bak
cp zig_edges.csv zig_edges.csv.bak
```

---

## STEP 2 — Write / overwrite the changed source files (copy each verbatim)

Verify each file's SHA-256 after copying, before running anything:

| File | Size (bytes) | SHA-256 (first 16 hex chars) |
|---|---|---|
{manifest}

{file_sections}

---

## STEP 2.5 — Regenerate the CREF layer and embeddings

If you ported the raw `CREF/*.csv` files (Asset Manifest item 1) rather than the
pre-built node/edge CSVs:

```bash
python3 consolidate_cref_data.py
```

Expected output ends with something like:
`Done! CREF: {cref_nodes} nodes, {cref_edges} edges. ZIG (reconciled): {zig_nodes} nodes, {zig_edges} edges.`
A small number of dropped edges (tens) referencing unknown node IDs is normal — it
usually means one stale ATT&CK technique ID in the raw CREF export that isn't in your
`mitre_nodes.csv` (e.g. a deprecated technique). Dozens is fine; hundreds is not —
stop and investigate if you see hundreds dropped.

Then, REGARDLESS of whether you regenerated or ported the CSVs, regenerate
embeddings — the node set changed, so any embeddings from before this extension are
stale (`embed_graph.py` will encode the wrong number of nodes otherwise):

```bash
python3 scripts/embed_graph.py
```

Skip this only if you are in keyword-fallback mode (no ML libraries) — the fallback
re-derives everything from the CSVs at query time, so there is nothing to regenerate.

---

## STEP 3 — VERIFICATION

**3.1 Full graph loads with all four frameworks:**

```bash
python3 scripts/graph_engine.py
```

Expected: `Knowledge Graph initialized with {total_nodes} nodes and {total_edges} edges.`
(numbers will differ slightly if your CREF/MITRE source data differs from the one this
guide was generated against).

**3.2 Spot-check the new node types resolve correctly:**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
for nid in ['CSA-01', 'CM1131']:
    print(nid, '->', e.query_node(nid))
# a zig_activity must still be type zig_activity, NOT cref_mitigation or anything else
act = e.query_node('ZIG-ACT-1.1.1')
assert act and act['type'] == 'zig_activity', 'ZIG reconciliation broke a node type!'
print('ZIG-ACT-1.1.1 ->', act)
"
```

Expected: `CSA-01` resolves to type `csa` ("Control Access"), `CM1131` resolves to
type `cref_mitigation` ("Active Deception"), and `ZIG-ACT-1.1.1` resolves to type
`zig_activity` with a CLEAN name ("Inventory User" — not PDF dot-leader garbage) and
the assertion passes.

**3.3 Direct ZIG-activity <-> ATT&CK edges exist (the new correlation path):**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
sub = e.crawl_subgraph('T1047', depth=2)
direct = [ed for ed in sub['edges'] if ed['target']=='T1047'
          and sub['nodes'].get(ed['source'], {{}}).get('type') == 'zig_activity']
assert direct, 'Expected at least one direct zig_activity -> T1047 edge'
print('Direct ZIG correlation for T1047:', direct)
"
```

Expected: at least one edge printed (T1047 / Windows Management Instrumentation is
one of the DoD Zero Trust Strategy crosswalk's example techniques).

**3.4 End-to-end report generation includes all 7 sections:**

```bash
python3 agent_batch_processor.py --limit 1
```

Open the generated report in `mock_output/` and confirm it has SEVEN numbered
sections (Executive Summary through POA&M), with Section 4 (CREF), Section 5 (NIST
800-53), and the CSA line in Section 1 all populated with real graph IDs — not
"None found in graph" for every field (a few "None found" per report is normal and
expected for techniques the new datasets don't cover; ALL of them saying so on every
report would mean the extension did not load).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A node's `type` looks wrong after this extension (e.g. an `M####` node now says `cref_mitigation`) | `consolidate_cref_data.py`'s native-mitigation collision check didn't run against the real `mitre_nodes.csv` (ran before base system was ported, or `mitre_ids` load was edited out) | Restore from your backups, re-port `mitre_nodes.csv`, re-run `consolidate_cref_data.py` |
| ZIG activity names reverted to garbled PDF text (dot-leaders, trailing `D-`) | `scripts/parse_zig_data.py` was re-run after this extension, overwriting the reconciliation | Re-run `consolidate_cref_data.py` again to re-apply the clean names, or restore `zig_nodes.csv.bak` / `zig_edges.csv.bak` from STEP 1 and re-run once |
| `graph_engine.py` node count didn't change after applying this extension | `cref_nodes.csv`/`cref_edges.csv` weren't actually created, or `scripts/graph_engine.py` wasn't updated to load the third file pair | Confirm STEP 2's `graph_engine.py` copy included the `cref_nodes.csv`/`cref_edges.csv` pair in `load_data()` |
| Embedding search returns nonsense after this extension | Ran `scripts/embed_graph.py` BEFORE `consolidate_cref_data.py` finished, or skipped STEP 2.5's embedding regeneration | Re-run `python3 scripts/embed_graph.py` now that the CSVs are final |
| Section 4/5/7 of a generated report say "None found in graph" for every finding you try | Either `cref_edges.csv` is empty/missing, or `scripts/graph_engine.py` isn't loading the third file pair | Run 3.1-3.3 above to isolate which layer is missing |

---

*This guide is generated by `build_cref_extension_guide.py` from the live source
files — regenerate it after any further change rather than editing it by hand.*
'''


if __name__ == "__main__":
    main()
````

---

## FILE: `README.md` (sha256=5c461835617fe545442f11ff65b856711a4cc0424bcc3a675d0ec6c64ce34512)

````markdown
# MITRE CSD-H — Threat Intelligence Knowledge Graph & Assessment Engine

A property graph unifying **MITRE ATT&CK**, **MITRE D3FEND**, the **NSA Zero Trust
Implementation Guide (ZIG)**, and **NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF)**
— including the DoD Zero Trust Strategy activity-level crosswalk, NIST SP 800-53
control mappings, and DoD Cyber Survivability Attributes — plus a Python engine and
pipeline that let an LLM agent translate unstructured red/blue team findings or
network vulnerability scans into standardized, framework-mapped Plans of Action &
Milestones (POA&M) spanning tactical, architectural, and compliance layers.

Designed for **air-gapped deployment**: if ML libraries are unavailable, semantic
search degrades automatically to ranked keyword search — see
`Air_Gapped_Deployment_Guide.md` for the full porting/reconstruction plan, or
`CREF_ZERO_TRUST_EXTENSION_GUIDE.md` if you already have the base system deployed
and are only adding the CREF/NIST/CSA layer.

## What's in the graph

| Framework | Contents |
|---|---|
| ATT&CK v19.1 | Tactics, techniques, mitigations, groups, software, campaigns, data components, detection strategies, analytics |
| D3FEND | Countermeasure techniques, tactics, defensive & offensive artifacts, ATT&CK↔D3FEND mappings |
| NSA ZIG | Pillars, capabilities, activities, technology-to-capability mappings |
| CREF (NIST SP 800-160 Vol. 2) | Goals, objectives, techniques, approaches, design principles, effects, direct ATT&CK↔CREF mappings |
| DoD Zero Trust Strategy | Direct ZIG-activity↔ATT&CK mappings, CM#### mitigation catalog, NIST SP 800-53 control citations |
| DoD Cyber Survivability Attributes | CSA-01..CSA-10, linked to CREF design principles and techniques |

Node files (`*_nodes.csv`): `id,type,name,description,url`.
Edge files (`*_edges.csv`): `source_id,target_id,relationship_type`.
ATT&CK/D3FEND also export as a single `ontology.json`.

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
| `scripts/consolidate_findings.py` | Groups CSV rows by ATT&CK technique so the graph crawl runs once per technique, not once per row |
| `scripts/llm_providers.py` | `get_provider()` — pluggable narrative/proofread/QA drafting (local/OpenAI/Gemini), degrading to a network-free heuristic fallback |
| `scripts/report_schema.py` | `build_report_json` / `render_markdown` — fills `assessment_template_consolidated.md` and its JSON twin |
| `assessment_template_consolidated.md` | Template for one-technique-many-hosts consolidated reports, incl. QA/QC section |
| `run_analyst_pipeline.py` | CLI: consolidate findings by technique, draft/proofread/QA via `--provider`, write `reports/*.md` + `*.json` |
| `consolidate_mitre_data.py` | Regenerates `mitre_nodes.csv` / `mitre_edges.csv` / `ontology.json` from the raw ATT&CK xlsx + D3FEND csv/ods |
| `scripts/parse_zig_data.py` | Regenerates `zig_nodes.csv` / `zig_edges.csv` from the ZIG PDF text extracts |
| `consolidate_cref_data.py` | Regenerates `cref_nodes.csv` / `cref_edges.csv` from `CREF/*.csv`, and reconciles the DoD ZT pillar/capability/activity taxonomy into the existing `zig_*.csv` (never re-run `scripts/parse_zig_data.py` afterward — it would overwrite the reconciliation) |
| `build_deployment_guide.py` | Regenerates `Air_Gapped_Deployment_Guide.md` from the live source files — run after any code change |
| `build_cref_extension_guide.py` | Regenerates `CREF_ZERO_TRUST_EXTENSION_GUIDE.md` — a delta guide for applying the CREF/NIST/CSA layer to an already-deployed air-gapped instance |
| `build_pipeline_addendum_guide.py` | Regenerates `ANALYST_PIPELINE_ADDENDUM_GUIDE.md` — a delta guide for adding the multi-provider analyst/proofreader/QA consolidation pipeline (backend only, no web UI/Docker/Tailscale) to an already-deployed air-gapped instance |
| `build_portable_bundle.py` | Regenerates `PORTABLE_RECONSTRUCTION_BUNDLE.md` — single-document, checksum-verified code transfer for text-only CDS |
| `import_to_neo4j.py` | Optional Neo4j loader (nodes + typed relationships) |

## Regenerating the data

When MITRE releases new data, drop the updated raw files in the repo root and run:

```bash
python3 consolidate_mitre_data.py
python3 consolidate_cref_data.py        # only if CREF/*.csv also changed; run AFTER consolidate_mitre_data.py
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py       # keep the deployment guide in sync
python3 build_cref_extension_guide.py   # keep the CREF extension guide in sync
python3 build_portable_bundle.py        # keep the CDS-transfer bundle in sync
```

## Multi-Provider Analyst Pipeline

`run_analyst_pipeline.py` consolidates `processed_assessment.csv` findings by
ATT&CK technique (one report per technique, covering every affected host) and
drafts/proofreads/QA-reviews each report via a pluggable LLM provider, chosen
with the `LLM_PROVIDER` env var (or `--provider`):

| `LLM_PROVIDER` | Backend |
|---|---|
| `local` | Any OpenAI-compatible local server (Ollama, LM Studio, vLLM, llama.cpp) |
| `openai` | Hosted OpenAI API (needs `OPENAI_API_KEY`) |
| `gemini` | Hosted Google Gemini API (needs `GEMINI_API_KEY`) |
| `none` (or unset) | Deterministic heuristic fallback — **the safe default**: no API keys, no network access, air-gap-friendly |

Any missing package/key falls back to `none` automatically with a warning —
it never raises. Run it with:

```bash
python3 run_analyst_pipeline.py
```

Reports land in `reports/` as matched `.md`/`.json` pairs; a deterministic
regex safety net cross-checks every bracketed framework ID (`[T1234]`,
`[D3-XXX]`, ...) in the drafted report against the graph and force-flags QA
if any don't resolve to a real node.

## Web UI (Tailscale)

A web UI (React frontend + FastAPI backend, PDF export via weasyprint) wraps
the graph engine and analyst pipeline. Once deployed on the owner's laptop it
is reachable tailnet-only at:

```
https://mitre-csdh.dikdik-macaroni.ts.net
```

Bring it up with:

```bash
cp .env.example .env          # then paste TS_AUTHKEY (see TAILSCALE_SIDECAR.md)
# optionally set LLM_PROVIDER + OPENAI_API_KEY / GEMINI_API_KEY / LOCAL_LLM_BASE_URL
docker compose up -d
```

Full sidecar recipe/gotchas: `TAILSCALE_SIDECAR.md`.

**This entire web UI / Docker / Tailscale layer is NOT part of the air-gapped
port.** `Air_Gapped_Deployment_Guide.md`, `CREF_ZERO_TRUST_EXTENSION_GUIDE.md`,
and `ANALYST_PIPELINE_ADDENDUM_GUIDE.md` cover the CLI/backend pipeline only
and remain fully independent of Docker, Tailscale, and this UI — none of them
require this layer to run.

## Using the graph elsewhere

- **Palantir Foundry/Gotham** — upload the node/edge CSVs (`mitre_*`, `zig_*`,
  `cref_*`); object type keyed on `id`, link type joining `source_id`/`target_id` → `id`.
- **Neo4j** — `python3 import_to_neo4j.py` (edit URI/credentials at the top; currently
  loads `mitre_*` only, extend it the same way for `zig_*`/`cref_*`), or `LOAD CSV` directly.
- **Python/NetworkX** — `from scripts.graph_engine import KnowledgeGraphEngine`
  (loads all three CSV pairs into one graph).
- **Web dashboards / BI** — `ontology.json` currently covers ATT&CK + D3FEND only; for
  ZIG/CREF join `zig_*.csv`/`cref_*.csv` relationally (Tableau, PowerBI) or load them
  into Cytoscape.js/D3.js alongside `ontology.json`.
````


---

*Generated by `build_portable_bundle.py` from the live source files. Regenerate
after any code change; never edit this document by hand.*
