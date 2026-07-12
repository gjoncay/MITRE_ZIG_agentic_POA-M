"""Generates PORTABLE_RECONSTRUCTION_BUNDLE.md — a single text-only markdown
document carrying every code/text file in this project, for cross-domain
solutions that block .py (and other non-text) files.

The data CSVs are NOT embedded: they are plain text and pass a CDS as-is.
Port them alongside the bundle. (If even they are blocked, the bundle still
contains the regeneration scripts + instructions in its Section 5.)

Each file is embedded under a header carrying its SHA-256, so the high-side
agent can extract everything mechanically with the small script in STEP 0
and prove the reconstruction is byte-exact.

Run after ANY change to the embedded files:
    python3 build_portable_bundle.py
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_NAME = "PORTABLE_RECONSTRUCTION_BUNDLE.md"

# Everything a high-side agent needs, in the order it should think about them.
EMBEDDED_FILES = [
    ("requirements.txt", "text"),
    ("scripts/graph_engine.py", "python"),
    ("scripts/embed_graph.py", "python"),
    ("scripts/ingest_assessment.py", "python"),
    ("agent_batch_processor.py", "python"),
    ("agent_crawl_example.py", "python"),
    ("assessment_template.md", "markdown"),
    ("threat_assessment_skill.md", "markdown"),
    ("consolidate_mitre_data.py", "python"),
    ("scripts/parse_zig_data.py", "python"),
    ("consolidate_cref_data.py", "python"),
    ("import_to_neo4j.py", "python"),
    ("build_deployment_guide.py", "python"),
    ("build_cref_extension_guide.py", "python"),
    ("README.md", "markdown"),
]


def read(relpath):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        return f.read()


def fence_for(content):
    """A backtick fence guaranteed longer than any backtick run in content."""
    longest = max((len(r) for r in re.findall(r"`+", content)), default=0)
    return "`" * max(4, longest + 1)


def embed(relpath, lang):
    content = read(relpath)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    fence = fence_for(content)
    return (f"## FILE: `{relpath}` (sha256={sha})\n\n"
            f"{fence}{lang}\n{content}{fence}\n"), sha, len(content.encode("utf-8"))


def main():
    sections, manifest_rows = [], []
    for relpath, lang in EMBEDDED_FILES:
        block, sha, size = embed(relpath, lang)
        sections.append(block)
        manifest_rows.append(f"| `{relpath}` | {size} | `{sha[:16]}...` |")

    extractor = read("extract_bundle.py")
    extractor_fence = fence_for(extractor)

    doc = DOC_TEMPLATE.format(
        manifest="\n".join(manifest_rows),
        file_count=len(EMBEDDED_FILES),
        extractor=f"{extractor_fence}python\n{extractor}{extractor_fence}",
        file_sections="\n---\n\n".join(sections),
    )

    out_path = os.path.join(BASE_DIR, OUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)

    # Self-test: run the real extractor against the bundle in a temp dir and
    # require byte-identical output for every embedded file.
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, "extract_bundle.py"), out_path],
            cwd=tmp, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit("SELF-TEST FAILED: checksum mismatch during re-extraction")
        for relpath, _ in EMBEDDED_FILES:
            with open(os.path.join(tmp, relpath), encoding="utf-8") as f:
                if f.read() != read(relpath):
                    raise SystemExit(f"SELF-TEST FAILED: {relpath} not byte-identical")

    print(f"Wrote {out_path} ({os.path.getsize(out_path)} bytes, "
          f"{len(EMBEDDED_FILES)} files embedded)")
    print("Self-test passed: extractor reproduces every file byte-for-byte.")


DOC_TEMPLATE = '''# PORTABLE RECONSTRUCTION BUNDLE — MITRE/ZIG Threat Assessment System

> **PROMPT — for the autonomous coding agent on the high-side network:**
> This single document contains the COMPLETE source code ({file_count} files) of a
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

{extractor}

Then, in an empty project directory containing this document:

```bash
python3 extract_bundle.py PORTABLE_RECONSTRUCTION_BUNDLE.md
```

Expected output: one `OK   <path>` line per file below, ending in
`{file_count} files written, 0 checksum failures`. **If any line says FAIL, the
document was corrupted or altered in transfer (smart quotes, stripped
whitespace, line-ending conversion are the usual suspects) — do not proceed;
fix the transfer or fall back to careful manual copy of that one file, then
re-run the extractor to re-verify.**

## Extraction manifest

| File | Bytes | SHA-256 (first 16) |
|---|---|---|
{manifest}

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
pd.DataFrame({{
    "IP": ["192.168.1.15"], "Hostname": ["DC-01"],
    "Finding": ["Kerberos Pre-Authentication disabled on service accounts"],
    "Severity": ["High"],
}}).to_csv("smoke_test.csv", index=False)
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

{file_sections}

---

*Generated by `build_portable_bundle.py` from the live source files. Regenerate
after any code change; never edit this document by hand.*
'''


if __name__ == "__main__":
    main()
