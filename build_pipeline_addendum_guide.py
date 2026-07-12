"""Generates ANALYST_PIPELINE_ADDENDUM_GUIDE.md — a DELTA guide for an agentic
coding agent that already has the base MITRE/D3FEND/ZIG/CREF knowledge graph
(from Air_Gapped_Deployment_Guide.md and/or CREF_ZERO_TRUST_EXTENSION_GUIDE.md)
deployed on an air-gapped network, and needs to add the multi-provider
analyst/proofreader/QA consolidation pipeline on top of it.

Scope: this covers ONLY the backend pipeline (consolidation + multi-provider
LLM analyst/proofread/QA + JSON/markdown output). There is no web UI, Docker,
or Tailscale component here — those ship in a separate later phase with their
own addendum, and are irrelevant to an air-gapped network regardless, since
that network has no Tailscale/internet path.

Every embedded file is byte-verified with a SHA-256, same rigor as
CREF_ZERO_TRUST_EXTENSION_GUIDE.md / build_cref_extension_guide.py, since this
is meant to be applied on a system you cannot easily SSH into to double-check.

Run after ANY change to the files listed in EMBEDDED_FILES below:
    python3 build_pipeline_addendum_guide.py
"""
import csv
import hashlib
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_NAME = "ANALYST_PIPELINE_ADDENDUM_GUIDE.md"

# Every file this addendum touches, new or modified, in the order a coding
# agent should write/overwrite them.
EMBEDDED_FILES = [
    ("scripts/llm_providers.py", "python"),
    ("scripts/consolidate_findings.py", "python"),
    ("scripts/report_schema.py", "python"),
    ("assessment_template_consolidated.md", "markdown"),
    ("run_analyst_pipeline.py", "python"),
]


def read(relpath):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        return f.read()


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
    total_nodes, total_edges = graph_counts()

    sections, manifest_rows = [], []
    for relpath, lang in EMBEDDED_FILES:
        block, sha, size = embed(relpath, lang)
        sections.append(block)
        manifest_rows.append(f"| `{relpath}` | {size} | `{sha[:16]}...` |")

    guide = GUIDE_TEMPLATE.format(
        total_nodes=total_nodes, total_edges=total_edges,
        manifest="\n".join(manifest_rows),
        file_sections="\n---\n\n".join(sections),
    )

    out_path = os.path.join(BASE_DIR, OUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out_path}")
    print(f"Verification numbers baked in: full graph {total_nodes} nodes / {total_edges} edges "
          f"(base + CREF layer, whatever is currently on disk)")


GUIDE_TEMPLATE = '''# Analyst Pipeline Addendum — Multi-Provider LLM Consolidation Layer

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> This is a DELTA guide, not a from-scratch build. It assumes the base MITRE
> ATT&CK/D3FEND/ZIG/CREF knowledge graph system from `Air_Gapped_Deployment_Guide.md`
> and/or `CREF_ZERO_TRUST_EXTENSION_GUIDE.md` is ALREADY deployed and working on this
> network — `mitre_nodes.csv`, `zig_nodes.csv`, `cref_nodes.csv` (and their `_edges`
> pairs) already exist, and `python3 scripts/graph_engine.py` already runs cleanly.
>
> **SCOPE — read this twice before touching any file.** This guide covers ONLY the
> backend pipeline: consolidating flattened findings by ATT&CK technique, drafting/
> proofreading/QA-reviewing report narratives via a pluggable LLM provider, and
> writing matched Markdown + JSON reports. **There is no web UI, no Docker, and no
> Tailscale component in this guide.** Those ship in a separate, later addendum with
> its own guide — and they are irrelevant to the air-gapped TS network covered here
> regardless, because that network has no Tailscale path and no internet egress at
> all. If you are looking for a dashboard or a `docker compose up`, you are in the
> wrong document.
>
> **HARD CONSTRAINT — not a suggestion.** On this air-gapped network, `LLM_PROVIDER`
> MUST be set to one of:
> - `local` — pointed at a locally-hosted, OpenAI-compatible model server reachable
>   ON THIS NETWORK (e.g. an internal vLLM/Ollama/LM Studio/llama.cpp endpoint), via
>   `LOCAL_LLM_BASE_URL`, or
> - `none` (or simply left unset) — the fully deterministic heuristic-fallback mode,
>   zero network calls, zero external dependencies beyond what the base system
>   already needs.
>
> **`LLM_PROVIDER=openai` and `LLM_PROVIDER=gemini` CANNOT be used on this network.**
> Both require internet egress to a hosted API (`api.openai.com`, `generativelanguage.
> googleapis.com`) that does not exist here. Do not attempt to work around this by
> tunneling, proxying, or hardcoding an API key "just to test it" — there is no route
> out, and any attempt will hang until it times out. If a task on this network asks
> for OpenAI- or Gemini-backed drafting, the correct action is to say so and fall
> back to `local` or `none`, not to find a way around the air gap.
>
> **Follow this document top to bottom. Do not improvise, do not "improve" the
> code, and do not skip verification steps.** Every source file you need is
> embedded below in full, each with a SHA-256 — copy each one byte-for-byte and
> verify the hash before trusting the copy.

---

## STEP 0 — Verify the base system before starting

```bash
python3 scripts/graph_engine.py
```

Expected: a node/edge count with no traceback, and (if the CREF extension is
already applied) `cref_*`/`CSA-*`/NIST mentions in the test output. If this
fails, fix the base deployment first — see `Air_Gapped_Deployment_Guide.md`
Section 11, or `CREF_ZERO_TRUST_EXTENSION_GUIDE.md`'s Troubleshooting table.

Also confirm `processed_assessment.csv` exists in the repo root (the output of
`scripts/ingest_assessment.py` — see `Air_Gapped_Deployment_Guide.md` Section
6.3). This pipeline reads that file; it does not ingest raw assessment reports
itself.

**Note on the CREF layer:** `scripts/consolidate_findings.py`'s graph crawl
(`crawl_correlation()`) reads CREF-approach, CREF-mitigation, NIST-control, and
CSA fields in addition to D3FEND/ZIG. If only the base system (no CREF
extension) is deployed, the pipeline still runs correctly — those fields will
render as "None found in graph" placeholders in Section 4/5 of each report,
per the base system's existing graceful-degradation contract. That is expected
behavior for techniques the CREF/DoD-ZT-Strategy datasets don't cover, not a
bug in this addendum. The verification numbers baked into this guide
({total_nodes} nodes / {total_edges} edges) reflect whatever combination of
base + CREF-extension CSVs was on disk when this guide was generated — do not
expect an exact match if your deployment order differed; expect the same
order of magnitude.

---

## Why this addendum exists

`agent_batch_processor.py` (the base system) and `scripts/consolidate_findings.py`
(this addendum) both do the same graph crawl per ATT&CK technique — but they solve
different problems:

1. **One-row-at-a-time doesn't scale to real assessments.** A flattened vulnerability
   scan routinely has dozens of rows that all resolve to the same technique (e.g. 40
   hosts all missing the same patch). Crawling the graph once per row is wasteful and
   produces 40 near-identical single-host reports nobody wants to read.
   `scripts/consolidate_findings.py` groups rows by resolved technique FIRST, then
   crawls once per unique technique — one report per technique, covering every
   affected host.
2. **The narrative text (Exploitation Scenario, Impact, POA&M) was previously
   hand-authored by whichever human or agent ran the batch script.** This addendum
   makes that narrative-drafting step pluggable across three backends — a local
   OpenAI-compatible model server, the hosted OpenAI API, the hosted Gemini API — or a
   fully deterministic, network-free heuristic fallback, selected by the
   `LLM_PROVIDER` env var (`scripts/llm_providers.py`). Every generated report also
   gets a machine-readable JSON twin (`scripts/report_schema.py`) and an automated
   QA pass that force-flags any report containing a bracketed framework ID that
   doesn't resolve to a real graph node — a deterministic hallucination safety net
   that runs regardless of which provider drafted the text.

**Every report this pipeline generates gets all three layers (tactical MITRE/D3FEND/
ZIG, architectural CREF, compliance NIST/CSA) plus a QA verdict — there is no
severity gate**, same convention as the base system and the CREF extension.

---

## Gotchas

1. **Never use `openai` or `gemini` for `LLM_PROVIDER` on this network.** Covered
   above as a hard constraint — repeated here because it is the single most likely
   mistake a coding agent makes on this system: seeing `OpenAIProvider`/`GeminiProvider`
   classes in `scripts/llm_providers.py` and assuming they're available options just
   because the code exists. The code exists so the SAME pipeline also works on a
   connected network; it does not mean both providers are usable here.
2. **`local` still requires the `openai` Python package.** `LocalOpenAICompatProvider`
   (used by `LLM_PROVIDER=local`) is implemented on top of the `openai` SDK, pointed at
   a different `base_url` — it talks to your internal server using the OpenAI
   chat-completions wire format, not the internet. If `pip install openai` cannot reach
   PyPI on this network either, port the wheel the same way you ported the Tier 2/3
   wheels in the base guide, or use `LLM_PROVIDER=none` instead.
3. **`get_provider()` NEVER raises — it always degrades to `HeuristicFallbackProvider`
   on any missing package or missing API key**, printing a `[Warning]` line first. A
   `[Warning]` in the console is not a failure; it is the pipeline doing exactly what
   it is designed to do. Only worry if the process exits non-zero or no reports land
   in `--output-dir`.
4. **`consolidate_findings.py`'s `crawl_correlation()` is a relocation, not a
   reimplementation, of `agent_batch_processor.py`'s steps 1.5–6.** If you find a bug
   in the graph-traversal logic, check whether the identical logic already exists in
   `agent_batch_processor.py` before "fixing" it here — fixing only one copy will make
   the two pipelines disagree on the same technique. (One such pre-existing quirk,
   already present in `agent_batch_processor.py` and NOT something to "fix" here: the
   Section 5 "Traceability" line's ZIG-activity ID, sourced from the `cref_mitigation`'s
   `implements_activity` edge, can point at a different ZIG activity than the Section 3
   "Relevant Activities" line, sourced from the direct `zig_activity -> technique`
   edge. Both IDs are real graph nodes — this is a data-provenance quirk in the CREF/ZT
   crosswalk source data, not an invented ID, and not in scope for this addendum to fix.)
5. **`run_analyst_pipeline.py`'s `_adapt_context_for_render()` and the two
   `full_affected_hosts`/uncapped-list overrides exist because two independently built
   modules use different field shapes for the same facts** (lists vs. pre-joined
   display strings, `finding_text` vs. `finding`, a display-capped `affected_hosts`
   vs. the full list JSON needs). If you ever hand-edit `_build_render_narrative()`,
   keep passing `full_affected_hosts=group_data["affected_hosts"]` at its call site in
   `main()` — that parameter is what makes the "N finding(s) across M unique host(s)"
   sentence count correctly once a technique group exceeds the 50-host markdown
   display cap. Dropping it silently undercounts unique hosts (confirmed with a
   60-distinct-host synthetic case: without it, the sentence read "60 finding(s)
   across 50 unique host(s)" — wrong; with it, "60 finding(s) across 60 unique
   host(s)" — correct). The embedded copy below already has this fix; this note is
   only for agents who resync from an older working tree instead of using the file
   verbatim.
6. **No emojis, no invented framework IDs** — same house rules as the base system and
   the CREF extension. The proofread/QA prompts in `scripts/llm_providers.py` already
   instruct any connected model not to alter bracketed `[ID]` tokens or POA&M
   checkboxes; `run_analyst_pipeline.py`'s `find_unknown_ids()` is the deterministic
   backstop that catches it anyway if a model ignores that instruction.

---

## Asset Manifest — what to port, in priority order

| Priority | Asset | Why |
|---|---|---|
| 1 | This guide | Contains every new source file in full, with hashes. |
| 2 | The already-deployed base graph CSVs (`mitre_*`, `zig_*`, `cref_*`) | Required — this addendum adds no new CSVs, it only adds code that queries the existing graph. |
| 3 | `processed_assessment.csv` (or the raw assessment report + `scripts/ingest_assessment.py`, already part of the base system) | The input this pipeline consumes. |
| 4 | The `openai` Python package (for `LLM_PROVIDER=local` only) | Only needed if you intend to run a local model server; skip entirely for `LLM_PROVIDER=none`. |
| 5 | A locally-hosted, OpenAI-compatible model server reachable on this network (for `LLM_PROVIDER=local` only) | Ollama / LM Studio / vLLM / llama.cpp, or an internal equivalent. Optional — `none` mode needs nothing here. |

**Decision tree:**
- No local model server on this network, or don't want to stand one up? → Use
  `LLM_PROVIDER=none` (or leave it unset). Skip Asset Manifest items 4–5 entirely.
  This is the recommended default for most air-gapped deployments.
- Have a local model server reachable on this network? → Port item 4, point
  `LOCAL_LLM_BASE_URL` at it, use `LLM_PROVIDER=local`.
- Considering `openai` or `gemini`? → Not an option here. See the hard constraint
  above.

---

## STEP 1 — Write the new source files (copy each verbatim)

Verify each file's SHA-256 after copying, before running anything:

| File | Size (bytes) | SHA-256 (first 16 hex chars) |
|---|---|---|
{manifest}

{file_sections}

---

## STEP 2 — Configure the provider for this network

Pick exactly one. Set it as an environment variable before running the pipeline
(or pass `--provider` on the command line, which overrides the env var).

**Recommended default — fully deterministic, zero network calls:**

```bash
export LLM_PROVIDER=none
# or simply leave LLM_PROVIDER unset entirely — "none" is the default
```

**If a local model server is reachable on this network:**

```bash
export LLM_PROVIDER=local
export LOCAL_LLM_BASE_URL=http://<internal-host>:<port>/v1   # OpenAI-compatible endpoint
export LOCAL_LLM_MODEL=<model-name-as-served>                 # e.g. llama3.1
# LOCAL_LLM_API_KEY defaults to "not-needed" -- most local servers ignore it
```

**Do NOT set either of these on this network:**

```bash
export LLM_PROVIDER=openai   # WRONG on air-gapped network -- requires internet egress
export LLM_PROVIDER=gemini   # WRONG on air-gapped network -- requires internet egress
```

---

## STEP 3 — Run the pipeline

```bash
python3 run_analyst_pipeline.py
```

Optional flags:

```bash
python3 run_analyst_pipeline.py --input processed_assessment.csv --output-dir reports --limit 5 --provider none
```

Expected console output (heuristic mode):

```text
Initializing Knowledge Graph Engine (loading vectors)...
Grouped findings into N unique technique(s); skipped K row(s) with no technique resolution.
Skipped K row(s) with no technique resolution.
Using provider: HeuristicFallbackProvider
Generated CONSOL-<T-code>: <finding_count> findings consolidated, QA=PASS
```

(repeated once per technique group). Reports land in `--output-dir` (default
`reports/`) as matched `CONSOL-<T-code>.md` / `CONSOL-<T-code>.json` pairs, one
pair per unique ATT&CK technique found in the input CSV.

---

## STEP 4 — VERIFICATION

**4.1 Clean run in heuristic mode completes with zero network calls:**

```bash
rm -rf reports
LLM_PROVIDER=none python3 run_analyst_pipeline.py
echo "Exit code: $?"
ls reports/
```

Expected: exit code `0`, and `reports/` contains one `.md` + `.json` pair per
technique group. Because this network has no route to the internet at all, a
completed run in normal runtime (no multi-minute hang followed by a timeout
traceback) is itself evidence that no network call was attempted — heuristic
mode's `HeuristicFallbackProvider` never imports `openai` or
`google.generativeai` in the first place, so there is nothing that could even
attempt one. Confirm the console printed `Using provider: HeuristicFallbackProvider`.

**4.2 Spot-check a generated report's framework IDs against the graph** (same
rigor as the base guide's Section 6.3 and the CREF extension's Section 3.2):

```bash
python3 -c "
import sys, json, re
sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
md = open('reports/<REPORT_ID>.md').read()   # substitute an actual generated report id
tokens = sorted(set(re.findall(r'\\[([A-Z0-9][A-Za-z0-9.\\-]*)\\](?!\\()', md)))
unknown = [t for t in tokens if e.query_node(t) is None]
print(f'{{len(tokens)}} bracketed IDs found, {{len(unknown)}} unresolved:', unknown)
assert not unknown, 'Found invented/unresolved framework ID(s) -- see unknown list above'
"
```

Expected: `0 unresolved`. This is the exact same deterministic check
`run_analyst_pipeline.py`'s own `find_unknown_ids()` runs internally before
writing the QA verdict — running it yourself here is a second, independent
confirmation using the ACTUAL file on disk, not just the code path that wrote it.

**4.3 JSON output is valid and mirrors the Markdown:**

```bash
python3 -c "
import json
d = json.load(open('reports/<REPORT_ID>.json'))       # substitute an actual generated report id
assert d['technique_id'] and d['report_id'] and d['generated_date']
assert d['qa_verdict'] in ('PASS', 'FLAG')
assert isinstance(d['affected_hosts'], list) and len(d['affected_hosts']) == d['finding_count']
print('JSON OK:', d['technique_id'], d['qa_verdict'], d['finding_count'], 'hosts')
"
```

Expected: no exception, and `finding_count` matches the number of rows in
`processed_assessment.csv` that resolved to that technique. Then manually
diff-check a few fields (technique name, D3FEND countermeasure, ZIG capability,
QA verdict/notes) between the `.md` and `.json` for the same report id — they
must agree, since both are built from the same `render_context`/`render_narrative`/
`qa_result` in `run_analyst_pipeline.py`'s `main()`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ImportError: The 'openai' package is required for OpenAIProvider` or the process appears to hang for a long time before eventually failing to connect | `LLM_PROVIDER=openai` or `LLM_PROVIDER=gemini` was set on this air-gapped box — the package may be absent (immediate `ImportError`, caught and degraded automatically) or present but unable to reach `api.openai.com`/`generativelanguage.googleapis.com` (connection timeout, since there is no route out) | Set `LLM_PROVIDER=local` (pointed at an internal server) or `LLM_PROVIDER=none`. This is expected failure behavior on this network, not a bug -- see the hard constraint at the top of this guide |
| `[Warning] LLM_PROVIDER=local but ...` then falls back to heuristic mode, even though you believe the local server is running | `LOCAL_LLM_BASE_URL` doesn't match where the server is actually listening, or the `openai` package isn't installed at all (triggers the `ImportError` branch, not the connection branch) | Confirm `pip show openai` succeeds; confirm `curl <LOCAL_LLM_BASE_URL>/models` (or equivalent) responds from the same host running the pipeline |
| Connection refused / `httpx.ConnectError` raised from inside `draft_narrative`/`proofread`/`qa_review` (NOT caught as a fallback) | `LLM_PROVIDER=local` is set correctly and the `openai` package IS installed, so `LocalOpenAICompatProvider` construction succeeds -- but no server is actually listening at `LOCAL_LLM_BASE_URL` at call time. Construction-time checks in `get_provider()` only catch `ImportError`/`ValueError`, not a connection failure that only surfaces on the first real request | Start the local model server before running the pipeline, or switch to `LLM_PROVIDER=none` if no server is available right now |
| A report's QA verdict is `FLAG` with a note like "Unresolved framework ID(s) detected by deterministic check: ..." | Either the provider genuinely hallucinated an ID not in the graph (real problem -- switch to `none` mode or fix the prompt/model), or a proofreading pass altered a bracketed ID token despite being instructed not to | Run STEP 4.2 above to see exactly which token(s) failed to resolve, then `engine.query_node()` them by hand to confirm they truly don't exist |
| `KeyError` inside `render_markdown()`/`build_report_json()` | `assessment_template_consolidated.md`'s placeholders and `scripts/report_schema.py`'s `.format()` kwargs have drifted apart -- you edited one file but not the other | Run `report_schema.py` directly (`python3 scripts/report_schema.py`) -- its `__main__` block lists every placeholder name in the template and smoke-tests the renderer against fake data with no graph dependency |
| "N finding(s) across N finding(s) unique host(s)" reads suspiciously low (e.g. fewer unique hosts than distinct hostnames you know are in the input) for a technique group with more than 50 affected hosts | You are running a hand-edited copy of `run_analyst_pipeline.py` where `_build_render_narrative()`'s call site dropped the `full_affected_hosts=group_data["affected_hosts"]` argument, so the unique-host count is being computed off `build_context()`'s 50-host markdown-display cap instead of the true full list | Re-copy `run_analyst_pipeline.py` verbatim from STEP 1 above (verify the SHA-256); do not hand-maintain a divergent copy |
| Section 4/5 (CREF/NIST) of every generated report says "None found in graph" | Either expected (the CREF extension was never applied to this deployment -- see the STEP 0 note above), or the CREF extension WAS applied but something regressed it | If you expect CREF data to be present, run `CREF_ZERO_TRUST_EXTENSION_GUIDE.md`'s own Section 3 verification steps to isolate whether the CREF layer itself is missing before assuming this addendum's code is at fault |
| `google.generativeai` import succeeds but prints a `FutureWarning` about the package being deprecated in favor of `google.genai` | Upstream Google SDK deprecation notice, unrelated to this pipeline's logic -- and moot on this network anyway since `gemini` is disallowed here | No action needed on an air-gapped deployment; if this codebase is later used on a connected network, treat it as a future migration note for `scripts/llm_providers.py`'s `GeminiProvider`, not an urgent fix |

---

*This guide is generated by `build_pipeline_addendum_guide.py` from the live
source files — regenerate it after any further change rather than editing it
by hand.*
'''


if __name__ == "__main__":
    main()
