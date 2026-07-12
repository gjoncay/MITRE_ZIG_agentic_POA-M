# Analyst Pipeline Addendum — Multi-Provider LLM Consolidation Layer

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
(5618 nodes / 43194 edges) reflect whatever combination of
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
| `scripts/llm_providers.py` | 17622 | `fbbe24cac02a8994...` |
| `scripts/consolidate_findings.py` | 14640 | `25c1ba39b3d0a964...` |
| `scripts/report_schema.py` | 16551 | `79402d325163d421...` |
| `assessment_template_consolidated.md` | 4280 | `0963452af09107f5...` |
| `run_analyst_pipeline.py` | 15656 | `9e90a129bf5aec4f...` |

### FILE: `scripts/llm_providers.py` (sha256=fbbe24cac02a89944c92b9320667716c198ccf67d20847a2b35bd700f8c49b05)

````python
import json
import os

try:
    from openai import OpenAI
    OPENAI_ENABLED = True
except ImportError:
    OPENAI_ENABLED = False

try:
    import google.generativeai as genai
    GEMINI_ENABLED = True
except ImportError:
    GEMINI_ENABLED = False

NARRATIVE_KEYS = [
    'exploitation_scenario', 'business_impact', 'csa_impact_summary',
    'architectural_recommendation', 'immediate_action', 'short_term_action',
    'long_term_action'
]

JSON_ONLY_CORRECTION = (
    "Your previous response could not be parsed as JSON. "
    "Reply with valid JSON only -- no markdown fences, no commentary, no leading or trailing text."
)


def _empty_narrative():
    return {k: "" for k in NARRATIVE_KEYS}


def _safe_qa_default(reason):
    return {"verdict": "FLAG", "notes": f"QA call failed: {reason}"}


def _build_narrative_prompt(context):
    ctx = context or {}
    facts = json.dumps(ctx, indent=2, default=str)
    return (
        "You are a senior cyber threat analyst writing an assessment report section. "
        "Using ONLY the graph facts supplied below (MITRE ATT&CK, D3FEND, ZIG/Zero Trust, "
        "CREF, NIST, and CSA data), write a professional narrative for a defense customer.\n\n"
        "Graph facts:\n"
        f"{facts}\n\n"
        "Respond with ONLY a JSON object with exactly these 7 string keys, no others:\n"
        f"{json.dumps(NARRATIVE_KEYS)}\n\n"
        "- exploitation_scenario: how an adversary would exploit this technique against the affected hosts.\n"
        "- business_impact: the operational/mission consequence if exploited.\n"
        "- csa_impact_summary: impact framed against the supplied Cyber Survivability Attribute (csa_name).\n"
        "- architectural_recommendation: a recommendation grounded in the supplied CREF approach/goal.\n"
        "- immediate_action: a specific, actionable near-term remediation step.\n"
        "- short_term_action: a specific short-term (weeks) remediation step.\n"
        "- long_term_action: a specific long-term architectural remediation step.\n\n"
        "Do not invent framework IDs that are not present in the supplied facts. "
        "No markdown fences, no commentary -- JSON only."
    )


def _build_proofread_prompt(markdown_text):
    return (
        "You are a technical editor proofreading a cybersecurity assessment report written in Markdown. "
        "Fix grammar, typos, spacing, and prose consistency ONLY.\n\n"
        "Strict rules:\n"
        "- Do NOT invent, remove, or alter any MITRE/D3FEND/ZIG/CREF/NIST/CSA identifiers.\n"
        "- Do NOT change the text inside any bracketed [ID] tokens.\n"
        "- Do NOT alter the POA&M checkboxes (e.g. '- [ ]' / '- [x]').\n"
        "- Do NOT add or remove any factual content, sections, or headings.\n\n"
        "Return ONLY the corrected Markdown document -- no commentary, no code fences.\n\n"
        "--- DOCUMENT START ---\n"
        f"{markdown_text}\n"
        "--- DOCUMENT END ---"
    )


def _build_qa_prompt(markdown_text, context):
    ctx = context or {}
    facts = json.dumps(ctx, indent=2, default=str)
    return (
        "You are a QA/QC reviewer checking a cybersecurity assessment report before it ships. "
        "You are given the report Markdown and the graph facts it was generated from.\n\n"
        "Graph facts:\n"
        f"{facts}\n\n"
        "Report:\n"
        f"{markdown_text}\n\n"
        "Check:\n"
        "1. Does the exploitation scenario logically follow from technique_name/technique_description?\n"
        "2. Does the severity framing look reasonable given the supplied findings?\n"
        "3. Is the POA&M (immediate/short-term/long-term actions) actionable and specific, not generic filler?\n"
        "4. Are there any obviously invented-sounding framework IDs not present in the supplied context?\n\n"
        "Respond with ONLY a JSON object: {\"verdict\": \"PASS\" or \"FLAG\", \"notes\": \"...\"}. "
        "No markdown fences, no commentary."
    )


def _parse_json_object(text):
    if text is None:
        return None
    cleaned = text.strip()
    if cleaned.startswith('```'):
        cleaned = cleaned.strip('`')
        if cleaned.lower().startswith('json'):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        return None


class LLMProvider:
    def draft_narrative(self, context: dict) -> dict:
        """Drafts the 7-field narrative section of a report from graph facts."""
        raise NotImplementedError

    def proofread(self, markdown_text: str) -> str:
        """Cleans grammar/prose in a report without touching identifiers or checkboxes."""
        raise NotImplementedError

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        """Reviews a drafted report for logical/factual soundness."""
        raise NotImplementedError


class _ChatCompletionMixin:
    """Shared draft/proofread/qa logic for providers that expose a single _complete(prompt) call."""

    def _complete(self, prompt: str) -> str:
        raise NotImplementedError

    def draft_narrative(self, context: dict) -> dict:
        prompt = _build_narrative_prompt(context)
        try:
            raw = self._complete(prompt)
        except Exception:
            # A runtime failure (e.g. the configured server is unreachable) should degrade
            # to legible heuristic text, not blank fields -- missing-package/key failures
            # are already caught earlier in get_provider(); this is the network/runtime case.
            return HeuristicFallbackProvider().draft_narrative(context)

        parsed = _parse_json_object(raw)
        if parsed is None:
            try:
                raw = self._complete(prompt + "\n\n" + JSON_ONLY_CORRECTION)
                parsed = _parse_json_object(raw)
            except Exception:
                parsed = None

        if not isinstance(parsed, dict):
            return HeuristicFallbackProvider().draft_narrative(context)

        return {k: str(parsed.get(k, "")) for k in NARRATIVE_KEYS}

    def proofread(self, markdown_text: str) -> str:
        try:
            result = self._complete(_build_proofread_prompt(markdown_text))
            return result if result else markdown_text
        except Exception:
            return markdown_text

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        prompt = _build_qa_prompt(markdown_text, context)
        try:
            raw = self._complete(prompt)
        except Exception as e:
            return _safe_qa_default(str(e))

        parsed = _parse_json_object(raw)
        if parsed is None:
            try:
                raw = self._complete(prompt + "\n\n" + JSON_ONLY_CORRECTION)
                parsed = _parse_json_object(raw)
            except Exception as e:
                return _safe_qa_default(str(e))

        if not isinstance(parsed, dict) or 'verdict' not in parsed:
            return _safe_qa_default("response was not valid JSON with a verdict field")

        verdict = parsed.get('verdict')
        if verdict not in ('PASS', 'FLAG'):
            verdict = 'FLAG'
        return {"verdict": verdict, "notes": str(parsed.get('notes', ''))}


class LocalOpenAICompatProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to any local server exposing the OpenAI chat-completions API (Ollama, LM Studio, vLLM, llama.cpp)."""

    def __init__(self):
        if not OPENAI_ENABLED:
            raise ImportError("The 'openai' package is required for LocalOpenAICompatProvider.")
        self.base_url = os.environ.get('LOCAL_LLM_BASE_URL', 'http://localhost:11434/v1')
        self.api_key = os.environ.get('LOCAL_LLM_API_KEY', 'not-needed')
        self.model = os.environ.get('LOCAL_LLM_MODEL', 'llama3.1')
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)

    def _complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class OpenAIProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to the hosted OpenAI API."""

    def __init__(self):
        if not OPENAI_ENABLED:
            raise ImportError("The 'openai' package is required for OpenAIProvider.")
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        self.model = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')
        self.client = OpenAI(api_key=api_key)

    def _complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class GeminiProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to the hosted Google Gemini API."""

    def __init__(self):
        if not GEMINI_ENABLED:
            raise ImportError("The 'google-generativeai' package is required for GeminiProvider.")
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        self.model_name = os.environ.get('GEMINI_MODEL', 'gemini-1.5-flash')
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(self.model_name)

    def _complete(self, prompt: str) -> str:
        response = self.model.generate_content(prompt)
        return response.text


# Sentinel strings crawl_correlation() (scripts/consolidate_findings.py) and
# agent_batch_processor.py return in place of a real name when the graph has
# no match for a given field -- they are never empty/None, so a plain
# truthiness check (`if csa_name:`) is always true and can't detect "nothing
# found". _is_unresolved() treats these (plus None/empty) as "nothing found".
_UNRESOLVED_MARKERS = {"None found in graph", "No matching ZIG activity"}


def _is_unresolved(value):
    return not value or value in _UNRESOLVED_MARKERS


class HeuristicFallbackProvider(LLMProvider):
    """Deterministic, network-free provider -- the air-gapped-safe default when no LLM is configured."""

    def draft_narrative(self, context: dict) -> dict:
        ctx = context or {}
        finding_text = ""
        affected_hosts = ctx.get('affected_hosts') or []
        if affected_hosts:
            finding_text = str(affected_hosts[0].get('finding_text', '') or '')
        hostname = affected_hosts[0].get('hostname', 'the affected host') if affected_hosts else 'the affected host'
        ip = affected_hosts[0].get('ip', 'N/A') if affected_hosts else 'N/A'

        if "Kerberos" in finding_text or "Delegation" in finding_text:
            exploitation = ("An adversary can request authentication tickets offline and crack them, "
                             "or use unconstrained delegation to impersonate highly privileged users "
                             "across the domain.")
            impact = "Complete domain compromise, unauthorized access to all Active Directory integrated services."
            imm_action = f"Disable unconstrained delegation or enforce Kerberos Pre-Auth on {hostname} ({ip})."
        elif "password" in finding_text.lower():
            exploitation = ("Adversaries can easily guess or brute-force administrative credentials "
                             "to gain elevated privileges.")
            impact = "Local system takeover leading to lateral movement across the network."
            imm_action = f"Immediately rotate the local administrator password on {hostname} ({ip}) and deploy LAPS."
        else:
            exploitation = "Adversaries could exploit this misconfiguration to execute unauthorized code or access sensitive data."
            impact = "Data breach or loss of system availability."
            imm_action = f"Investigate and patch/reconfigure {hostname} ({ip})."

        csa_name = ctx.get('csa_name')
        csa_impact_summary = (
            f"This finding threatens the ability to {csa_name.lower()}."
            if not _is_unresolved(csa_name) else
            "No DoD Cyber Survivability Attribute mapped to this technique in the graph."
        )

        mitre_name = ctx.get('technique_name', 'this technique')
        cref_approach = ctx.get('cref_approach')
        cref_goal = ctx.get('cref_goal')
        architectural_recommendation = (
            f"Because {mitre_name} can recur in forms tactical controls won't catch, "
            f"engineer for {str(cref_approach).lower()} ({str(cref_goal).lower()} the mission) "
            f"rather than relying solely on tactical blockers."
            if not _is_unresolved(cref_approach) else
            "No CREF architectural approach mapped to this technique in the graph; "
            "tactical controls are the primary mitigation for this finding."
        )

        zig_cap_name = ctx.get('zig_capability_name')
        cref_approach_resolved = not _is_unresolved(cref_approach)
        zig_cap_resolved = not _is_unresolved(zig_cap_name)
        long_term_action = (
            f"Integrate {zig_cap_name} architecture fully; adopt {cref_approach} per Section 4."
            if cref_approach_resolved and zig_cap_resolved else
            f"Integrate {zig_cap_name} architecture fully." if zig_cap_resolved else
            "Integrate a Zero Trust architecture capability fully."
        )

        return {
            "exploitation_scenario": exploitation,
            "business_impact": impact,
            "csa_impact_summary": csa_impact_summary,
            "architectural_recommendation": architectural_recommendation,
            "immediate_action": imm_action,
            "short_term_action": "Implement continuous monitoring for this vulnerability class.",
            "long_term_action": long_term_action,
        }

    def proofread(self, markdown_text: str) -> str:
        return markdown_text

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        return {"verdict": "PASS", "notes": "Heuristic mode: no LLM QA performed; review manually."}


def get_provider(name=None) -> LLMProvider:
    """Factory that always returns a usable provider, degrading to the heuristic fallback on any error."""
    name = (name or os.environ.get('LLM_PROVIDER', 'none') or 'none').lower()

    if name == 'local':
        try:
            return LocalOpenAICompatProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=local but the 'openai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError as e:
            print(f"[Warning] LLM_PROVIDER=local but {e} Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    if name == 'openai':
        try:
            return OpenAIProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=openai but the 'openai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError:
            print("[Warning] LLM_PROVIDER=openai but OPENAI_API_KEY is not set. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    if name == 'gemini':
        try:
            return GeminiProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=gemini but the 'google-generativeai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError:
            print("[Warning] LLM_PROVIDER=gemini but GEMINI_API_KEY is not set. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    return HeuristicFallbackProvider()


if __name__ == "__main__":
    provider = get_provider()
    print(f"Using provider: {type(provider).__name__}")

    sample_context = {
        "technique_id": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets",
        "technique_description": "Adversaries may attempt to subvert Kerberos ticketing.",
        "tactic": "Credential Access",
        "affected_hosts": [
            {"ip": "10.0.0.12", "hostname": "DC01", "finding_text": "Unconstrained Kerberos Delegation enabled on DC01", "severity": "Critical"}
        ],
        "finding_count": 1,
        "severity_breakdown": {"Critical": 1},
        "d3fend_countermeasures": ["[D3-KAM] Kerberos Authentication Monitoring"],
        "d3fend_artifacts": [],
        "mitre_analytics": [],
        "mitre_mitigations": [],
        "zig_pillar": "Identity",
        "zig_capability_id": "ZIG-CAP-1.1",
        "zig_capability_name": "Authentication",
        "zig_activity_id": "ZIG-ACT-1.1.1",
        "zig_activity_name": "Enforce Kerberos Pre-Auth",
        "zig_technologies": [],
        "cref_goal": "Assure Mission",
        "cref_objective": "Prevent Escalation",
        "cref_technique": "Privilege Restriction",
        "cref_approach": "Least Privilege Enforcement",
        "cref_approach_id": "CREF-APP-3",
        "cref_effect": "Reduce Attack Surface",
        "cref_mitigation_id": "CREF-MIT-3",
        "cref_mitigation_name": "Delegation Hardening",
        "nist_controls": ["AC-6"],
        "csa_name": "Prevent Escalation of Privileges",
        "traceability": "Implements CREF Approach CREF-APP-3 / ZIG Activity ZIG-ACT-1.1.1",
    }

    result = provider.draft_narrative(sample_context)
    print(json.dumps(result, indent=2))
````

---

### FILE: `scripts/consolidate_findings.py` (sha256=25c1ba39b3d0a964e144d50f54fb601091ecf663178414574cdc0893e1626c34)

````python
"""
Consolidates CSV findings by MITRE ATT&CK technique before running the graph
correlation crawl, instead of agent_batch_processor.py's one-crawl-per-row
behavior. Many rows in a flattened assessment resolve to the same underlying
technique; this groups them first so crawl_correlation() (the expensive
graph traversal) runs once per unique technique, not once per finding row.

The graph-traversal logic in crawl_correlation() is a direct extraction of
the logic already in agent_batch_processor.py (steps 1.5-6) -- it is not a
reimplementation, just relocated so it can run per-technique-group instead
of per-row.
"""
import sys
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))
from graph_engine import KnowledgeGraphEngine


def first_present(row, candidates, default="Unknown"):
    """Returns the first non-empty value among candidate column names (schemas vary per team)."""
    for col in candidates:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return default


def resolve_technique(engine, finding_text):
    """Semantic-search a finding to its MITRE ATT&CK technique.

    Same filter rule as agent_batch_processor.py: take the first semantic
    search hit whose node id looks like a technique id ('T' followed by a
    digit). Returns (node_id, node_data, score) or None.
    """
    mitre_results = engine.semantic_search(finding_text, top_k=20)
    for nid, ndata, score in mitre_results:
        if nid.startswith('T') and len(nid) > 1 and nid[1].isdigit():
            return (nid, ndata, score)
    return None


def group_findings_by_technique(engine, df):
    """Groups CSV rows by resolved ATT&CK technique id.

    Returns (groups_dict, skipped_count) where groups_dict maps
    technique_id -> {technique_name, technique_description, affected_hosts,
    severity_breakdown}.
    """
    groups = {}
    skipped_count = 0

    for index, row in df.iterrows():
        finding_text = first_present(row, ['Finding', 'Observation', 'Vulnerability', 'Description'])
        ip = first_present(row, ['IP', 'Target Address', 'Address'], default="N/A")
        hostname = first_present(row, ['Hostname', 'Host', 'Target'], default="N/A")
        severity = first_present(row, ['Severity'], default="Unknown")

        mitre_node = resolve_technique(engine, finding_text)
        if not mitre_node:
            print(f"[{index}] No MITRE technique found for '{finding_text}' -- skipping")
            skipped_count += 1
            continue

        t_code, mitre_node_data, score = mitre_node

        if t_code not in groups:
            groups[t_code] = {
                "technique_name": mitre_node_data.get('name', 'Unknown'),
                "technique_description": mitre_node_data.get('description', 'Unknown'),
                "affected_hosts": [],
                "severity_breakdown": {},
            }

        group = groups[t_code]
        group["affected_hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "finding_text": finding_text,
            "severity": severity,
        })
        group["severity_breakdown"][severity] = group["severity_breakdown"].get(severity, 0) + 1

    print(f"Grouped findings into {len(groups)} unique technique(s); skipped {skipped_count} row(s) with no technique resolution.")
    return groups, skipped_count


def crawl_correlation(engine, t_code):
    """Runs the graph correlation crawl once for a given technique id.

    This is a direct extraction of agent_batch_processor.py's steps 1.5-6
    (tactic resolution, D3FEND/analytics/mitigations collection, ZIG
    activity/capability/pillar resolution, CREF approach/technique/
    objective/goal/effect walk-up, CREF mitigation/NIST controls, and CSA
    lookup) -- same graph queries, same fallback rules, unchanged.
    """
    mitre_node_data = engine.query_node(t_code) or {}
    mitre_name = mitre_node_data.get('name', 'Unknown')

    # 1.5 Extract Tactic (belongs_to_tactic points at a TA-node; resolve its name)
    mitre_tactic = "Unknown Tactic"
    for u, v, data in engine.graph.out_edges(t_code, data=True):
        if data.get('relationship') == 'belongs_to_tactic':
            tactic_node = engine.query_node(v)
            mitre_tactic = f"[{v}] {tactic_node.get('name', v)}" if tactic_node else v
            break

    # 2. Mitigation Crawl (D3FEND & Supplementals)
    mitre_subgraph = engine.crawl_subgraph(t_code, depth=2)
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
            if edge.get('target') != t_code:
                continue
            src_data = mitre_subgraph['nodes'].get(edge['source'], {})
            src_type = src_data.get('type')
            if src_type == 'zig_activity' and edge.get('relationship') == 'mitigates':
                zig_activities_direct.append((edge['source'], src_data))
            elif src_type == 'cref_approach' and edge.get('relationship') == 'mitigates_architecturally':
                cref_approaches.append((edge['source'], src_data))
            elif src_type == 'cref_mitigation' and edge.get('relationship') == 'mitigates':
                cref_mitigations.append((edge['source'], src_data))

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
    traceability = (
        f"Implements CREF Approach {cref_approach_id} / ZIG Activity {zig_activity_id_from_mitigation or zig_activity_id}"
        if cref_mitigations else
        "N/A — no CREF/ATT&CK mitigation mapped to this technique"
    )

    # 6. Cyber Survivability Attribute (CSA) impact, from the resolved CREF technique.
    csa_name = "None found in graph"
    if cref_technique_id_found:
        for u, v, data in engine.graph.in_edges(cref_technique_id_found, data=True):
            if data.get('relationship') == 'associated_with_technique':
                csa_node = engine.query_node(u)
                if csa_node:
                    csa_name = csa_node.get('name', u)
                break

    zig_technologies = [f"[{nid}] {ndata.get('name', nid)}" for nid, ndata in zig_techs]

    return {
        "tactic": mitre_tactic,
        "technique_description": mitre_node_data.get('description', 'Unknown'),
        "d3fend_countermeasures": d3fend_countermeasures,
        "d3fend_artifacts": d3fend_artifacts,
        "mitre_analytics": analytics,
        "mitre_mitigations": mitigations,
        "zig_pillar": zig_pillar,
        "zig_activity_id": zig_activity_id,
        "zig_activity_name": zig_activity_name,
        "zig_capability_id": zig_cap_id,
        "zig_capability_name": zig_cap_name,
        "zig_technologies": zig_technologies,
        "cref_goal": cref_goal,
        "cref_objective": cref_objective,
        "cref_technique": cref_technique_name,
        "cref_approach": cref_approach_name,
        "cref_approach_id": cref_approach_id,
        "cref_effect": cref_effect,
        "cref_mitigation_id": cref_mitigation_id,
        "cref_mitigation_name": cref_mitigation_name,
        "nist_controls": nist_controls,
        "traceability": traceability,
        "csa_name": csa_name,
    }


def build_context(t_code, group_data, correlation_data, max_hosts_displayed=50):
    """Merges group_data and correlation_data into the flat context dict draft_narrative() consumes."""
    affected_hosts = group_data["affected_hosts"]
    finding_count = len(affected_hosts)

    displayed_hosts = affected_hosts[:max_hosts_displayed]
    hosts_truncated_note = None
    if finding_count > max_hosts_displayed:
        hosts_truncated_note = (
            f"Showing first {max_hosts_displayed} of {finding_count} affected hosts."
        )

    context = {
        "technique_id": t_code,
        "technique_name": group_data["technique_name"],
        "technique_description": group_data["technique_description"],
        "affected_hosts": displayed_hosts,
        "finding_count": finding_count,
        "severity_breakdown": group_data["severity_breakdown"],
        "hosts_truncated_note": hosts_truncated_note,
    }
    context.update(correlation_data)
    return context


if __name__ == "__main__":
    input_csv = os.path.join(BASE_DIR, "processed_assessment.csv")

    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()

    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"Could not find {input_csv}. Did you run scripts/ingest_assessment.py first?")
        sys.exit(1)

    groups, skipped_count = group_findings_by_technique(engine, df)

    for t_code in list(groups.keys())[:2]:
        group_data = groups[t_code]
        correlation_data = crawl_correlation(engine, t_code)
        context = build_context(t_code, group_data, correlation_data)
        print(f"\nTechnique: {t_code}")
        print(f"Context keys: {sorted(context.keys())}")
````

---

### FILE: `scripts/report_schema.py` (sha256=79402d325163d421c0ba71eeb0ff001a14ebce07792abdd44961a1674794cebb)

````python
"""
report_schema.py

Shared schema/rendering layer for the CONSOLIDATED (many-hosts-per-technique)
assessment report pipeline. This module is intentionally self-contained: it
does not import graph_engine, agent_batch_processor, or any QA module, so it
can be developed and tested independently of those other pieces.

Two entry points:

  build_report_json(t_code, context, narrative, qa_result)
      -> plain, JSON-serializable dict mirroring every field that ends up in
         the rendered markdown, PLUS the full (uncapped) affected_hosts list
         for machine consumption.

  render_markdown(template_str, report_id, generated_date, t_code, context,
                   narrative, qa_result)
      -> the filled assessment_template_consolidated.md markdown string.

Expected shapes of the four "data" arguments (all caller-supplied; this
module never calls datetime.now() or any graph/QA code itself):

  context: dict, technique-level facts pulled from the knowledge graph, e.g.
      {
        "technique_name": str,
        "tactic": str,
        "technique_description": str,
        "mitre_analytics": str,
        "mitre_mitigations": str,
        "d3fend_countermeasure_1": str,
        "d3fend_countermeasure_2": str,
        "d3fend_artifacts": str,
        "zig_pillar_name": str,
        "zig_capability_id": str,
        "zig_capability_name": str,
        "zig_activity_1": str,
        "zig_technology_1": str,
        "zig_technology_2": str,
        "cref_goal": str,
        "cref_objective": str,
        "cref_technique": str,
        "cref_approach": str,
        "cref_effect": str,
        "cref_recommendation": str,
        "cref_mitigation_id": str,
        "cref_mitigation_name": str,
        "nist_800_53_controls": str,
        "traceability": str,
        "csa_name": str,
        "csa_impact_summary": str,
        "finding_count": int,                     # optional; derived from
                                                    # len(affected_hosts) if
                                                    # omitted
        "severity_breakdown": {"Critical": 3, "High": 9, ...},
        "affected_hosts": [
            {"ip": "10.0.0.5", "hostname": "web01",
             "finding": "...", "severity": "Critical"},
            ...
        ],
        "_display_cap": 50,                        # optional, markdown-only
        "report_id": str,                           # read by
        "generated_date": str,                      # build_report_json only
                                                      # (render_markdown gets
                                                      # these as explicit args
                                                      # instead)
      }

  narrative: dict, the 7 agent-authored "So What" / POA&M / implementation
      fields that are NOT pulled from the graph:
      {
        "threat_input_summary": str,
        "exploitation_scenario": str,
        "business_impact": str,
        "immediate_action": str,
        "short_term_action": str,
        "long_term_action": str,
        "technology_implementation_notes": str,
      }

  qa_result: dict, the automated QA pass's verdict:
      {"verdict": "PASS" | "FLAG", "notes": str}
"""

import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(BASE_DIR, "assessment_template_consolidated.md")


def build_report_json(t_code, context, narrative, qa_result):
    """Pure function of its inputs -> plain, JSON-serializable dict.

    Does NOT generate report_id/generated_date itself: both are read from
    context (caller-supplied) so this function stays a pure function of
    (t_code, context, narrative, qa_result) with no hidden clock/ID calls.
    """
    affected_hosts = context.get("affected_hosts", [])
    finding_count = context.get("finding_count", len(affected_hosts))

    return {
        # Identity / provenance (caller-supplied, never generated here)
        "report_id": context.get("report_id"),
        "generated_date": context.get("generated_date"),

        # MITRE technique-level identity
        "technique_id": t_code,
        "technique_name": context.get("technique_name"),
        "tactic": context.get("tactic"),
        "technique_description": context.get("technique_description"),
        "mitre_analytics": context.get("mitre_analytics"),
        "mitre_mitigations": context.get("mitre_mitigations"),

        # Scope of this consolidated report
        "finding_count": finding_count,
        "severity_breakdown": context.get("severity_breakdown", {}),
        "affected_hosts": affected_hosts,  # full list, not capped

        # D3FEND
        "d3fend_countermeasure_1": context.get("d3fend_countermeasure_1"),
        "d3fend_countermeasure_2": context.get("d3fend_countermeasure_2"),
        "d3fend_artifacts": context.get("d3fend_artifacts"),

        # ZIG
        "zig_pillar_name": context.get("zig_pillar_name"),
        "zig_capability_id": context.get("zig_capability_id"),
        "zig_capability_name": context.get("zig_capability_name"),
        "zig_activity_1": context.get("zig_activity_1"),
        "zig_technology_1": context.get("zig_technology_1"),
        "zig_technology_2": context.get("zig_technology_2"),

        # CREF
        "cref_goal": context.get("cref_goal"),
        "cref_objective": context.get("cref_objective"),
        "cref_technique": context.get("cref_technique"),
        "cref_approach": context.get("cref_approach"),
        "cref_effect": context.get("cref_effect"),
        "cref_recommendation": context.get("cref_recommendation"),
        "cref_mitigation_id": context.get("cref_mitigation_id"),
        "cref_mitigation_name": context.get("cref_mitigation_name"),

        # NIST SP 800-53
        "nist_800_53_controls": context.get("nist_800_53_controls"),
        "traceability": context.get("traceability"),

        # CSA (mission-level framing)
        "csa_name": context.get("csa_name"),
        "csa_impact_summary": context.get("csa_impact_summary"),

        # Narrative (agent-authored) fields
        "threat_input_summary": narrative.get("threat_input_summary"),
        "exploitation_scenario": narrative.get("exploitation_scenario"),
        "business_impact": narrative.get("business_impact"),
        "immediate_action": narrative.get("immediate_action"),
        "short_term_action": narrative.get("short_term_action"),
        "long_term_action": narrative.get("long_term_action"),
        "technology_implementation_notes": narrative.get(
            "technology_implementation_notes"
        ),

        # QA/QC
        "qa_verdict": qa_result.get("verdict"),
        "qa_notes": qa_result.get("notes"),
    }


def _build_affected_hosts_table(context):
    """Render the {AFFECTED_HOSTS_TABLE} markdown table, capped for display.

    Full data always lives in build_report_json()'s uncapped affected_hosts
    list -- the cap here is purely about keeping the markdown report
    readable.
    """
    affected_hosts = context.get("affected_hosts", [])
    display_cap = context.get("_display_cap", 50)
    finding_count = context.get("finding_count", len(affected_hosts))

    displayed = affected_hosts[:display_cap]

    lines = ["| IP | Hostname | Finding | Severity |", "|---|---|---|---|"]
    for host in displayed:
        lines.append(
            "| {ip} | {hostname} | {finding} | {severity} |".format(
                ip=host.get("ip", "N/A"),
                hostname=host.get("hostname", "N/A"),
                finding=host.get("finding", "N/A"),
                severity=host.get("severity", "N/A"),
            )
        )

    if finding_count > len(displayed):
        remaining = finding_count - len(displayed)
        lines.append("")
        lines.append(
            f"*...and {remaining} more hosts (see JSON for full list)*"
        )

    return "\n".join(lines)


def _build_severity_breakdown_str(context):
    """Render {SEVERITY_BREAKDOWN} as a comma-joined "Level: count" string."""
    severity_breakdown = context.get("severity_breakdown", {})
    return ", ".join(
        f"{level}: {count}" for level, count in severity_breakdown.items()
    )


def render_markdown(
    template_str, report_id, generated_date, t_code, context, narrative, qa_result
):
    """Fill every placeholder in assessment_template_consolidated.md.

    If a placeholder in template_str has no matching kwarg below, str.format
    raises KeyError -- that is intentional and is left to propagate. A
    mismatched placeholder is a real bug (template and renderer drifted
    apart) and must surface loudly rather than being swallowed.
    """
    affected_hosts_table = _build_affected_hosts_table(context)
    severity_breakdown_str = _build_severity_breakdown_str(context)
    finding_count = context.get("finding_count", len(context.get("affected_hosts", [])))

    return template_str.format(
        DATE=generated_date,
        ASSESSMENT_ID=report_id,
        FINDING_COUNT=finding_count,
        SEVERITY_BREAKDOWN=severity_breakdown_str,
        THREAT_INPUT_SUMMARY=narrative["threat_input_summary"],
        AFFECTED_HOSTS_TABLE=affected_hosts_table,
        EXPLOITATION_SCENARIO=narrative["exploitation_scenario"],
        BUSINESS_IMPACT=narrative["business_impact"],
        CSA_NAME=context["csa_name"],
        CSA_IMPACT_SUMMARY=context["csa_impact_summary"],
        MITRE_TACTIC=context["tactic"],
        MITRE_TECHNIQUE_ID=t_code,
        MITRE_TECHNIQUE_NAME=context["technique_name"],
        MITRE_TECHNIQUE_DESCRIPTION=context["technique_description"],
        MITRE_ANALYTICS=context["mitre_analytics"],
        MITRE_MITIGATIONS=context["mitre_mitigations"],
        D3FEND_COUNTERMEASURE_1=context["d3fend_countermeasure_1"],
        D3FEND_COUNTERMEASURE_2=context["d3fend_countermeasure_2"],
        D3FEND_ARTIFACTS=context["d3fend_artifacts"],
        ZIG_PILLAR_NAME=context["zig_pillar_name"],
        ZIG_CAPABILITY_ID=context["zig_capability_id"],
        ZIG_CAPABILITY_NAME=context["zig_capability_name"],
        ZIG_ACTIVITY_1=context["zig_activity_1"],
        CREF_GOAL=context["cref_goal"],
        CREF_OBJECTIVE=context["cref_objective"],
        CREF_TECHNIQUE=context["cref_technique"],
        CREF_APPROACH=context["cref_approach"],
        CREF_EFFECT=context["cref_effect"],
        CREF_RECOMMENDATION=context["cref_recommendation"],
        CREF_MITIGATION_ID=context["cref_mitigation_id"],
        CREF_MITIGATION_NAME=context["cref_mitigation_name"],
        NIST_800_53_CONTROLS=context["nist_800_53_controls"],
        TRACEABILITY=context["traceability"],
        ZIG_TECHNOLOGY_1=context["zig_technology_1"],
        ZIG_TECHNOLOGY_2=context["zig_technology_2"],
        TECHNOLOGY_IMPLEMENTATION_NOTES=narrative["technology_implementation_notes"],
        IMMEDIATE_ACTION=narrative["immediate_action"],
        SHORT_TERM_ACTION=narrative["short_term_action"],
        LONG_TERM_ACTION=narrative["long_term_action"],
        QA_VERDICT=qa_result["verdict"],
        QA_NOTES=qa_result["notes"],
    )


def _extract_placeholder_names(template_str):
    """Return the sorted, de-duplicated {PLACEHOLDER} names used in a template."""
    return sorted(set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template_str)))


if __name__ == "__main__":
    # --- Hand-built fake inputs (no dependency on graph_engine / QA module) ---
    fake_t_code = "T1558.001"

    fake_context = {
        "technique_name": "Golden Ticket",
        "tactic": "[TA0006] Credential Access",
        "technique_description": "Adversaries who have the Kerberos ticket-"
        "granting ticket (TGT) hash may forge Kerberos tickets.",
        "mitre_analytics": "  - [AN0031] Unusual TGT request volume",
        "mitre_mitigations": "  - [M1015] Active Directory Configuration",
        "d3fend_countermeasure_1": "[D3-CRO] Credential Rotation",
        "d3fend_countermeasure_2": "[D3-AL] Audit Log Analysis",
        "d3fend_artifacts": "[DC0001] Active Directory, [DC0002] Kerberos Ticket",
        "zig_pillar_name": "Identity",
        "zig_capability_id": "1.2",
        "zig_capability_name": "Identity Federation & User Credentialing",
        "zig_activity_1": "[ACT-1.2.3] Enforce Kerberos pre-authentication",
        "zig_technology_1": "[TECH-01] Privileged Access Management",
        "zig_technology_2": "[TECH-02] LAPS",
        "cref_goal": "Recover",
        "cref_objective": "Reduce recovery time",
        "cref_technique": "Non-Persistence",
        "cref_approach": "Non-Persistent Information",
        "cref_effect": "Contain",
        "cref_recommendation": "Because Golden Ticket attacks can recur in "
        "forms tactical controls won't catch, engineer for non-persistent "
        "credential material (recover the mission) rather than relying "
        "solely on tactical blockers alone.",
        "cref_mitigation_id": "CM0042",
        "cref_mitigation_name": "Credential Lifetime Reduction",
        "nist_800_53_controls": "AC-4(3), IA-5(13)",
        "traceability": "Implements CREF Approach CA0017 / ZIG Activity ACT-1.2.3",
        "csa_name": "Control Access",
        "csa_impact_summary": "This finding threatens the ability to control "
        "access to mission systems.",
        "finding_count": 14,
        "severity_breakdown": {"Critical": 3, "High": 9, "Medium": 2},
        "affected_hosts": [
            {
                "ip": "10.1.1.5",
                "hostname": "dc01",
                "finding": "Unconstrained delegation enabled",
                "severity": "Critical",
            },
            {
                "ip": "10.1.1.6",
                "hostname": "dc02",
                "finding": "Unconstrained delegation enabled",
                "severity": "Critical",
            },
            {
                "ip": "10.1.2.10",
                "hostname": "app03",
                "finding": "Weak Kerberos pre-auth config",
                "severity": "High",
            },
        ],
        "_display_cap": 2,  # deliberately small, to exercise the "N more" path
        "report_id": "ASMT-CONSOL-0001",
        "generated_date": "2026-07-12",
    }

    fake_narrative = {
        "threat_input_summary": "14 hosts across the domain resolved to "
        "Golden Ticket / forged Kerberos ticket behavior.",
        "exploitation_scenario": "An adversary with the krbtgt hash can "
        "forge TGTs offline and impersonate any account domain-wide.",
        "business_impact": "Complete domain compromise across all listed hosts.",
        "immediate_action": "Rotate the krbtgt password (twice) and audit "
        "unconstrained delegation on every host listed above.",
        "short_term_action": "Deploy continuous monitoring for anomalous "
        "TGT requests across all affected hosts.",
        "long_term_action": "Adopt non-persistent credential architecture "
        "per Section 4 across the affected host population.",
        "technology_implementation_notes": "Ensure configurations align "
        "with vendor security baselines on every affected host.",
    }

    fake_qa_result = {
        "verdict": "PASS",
        "notes": "All 14 findings mapped to T1558.001 with graph-sourced "
        "D3FEND/ZIG/CREF/NIST fields; no fabricated identifiers detected.",
    }

    report_json = build_report_json(
        fake_t_code, fake_context, fake_narrative, fake_qa_result
    )
    assert report_json["technique_id"] == fake_t_code
    assert report_json["finding_count"] == 14
    assert len(report_json["affected_hosts"]) == 3  # uncapped, machine list
    assert report_json["report_id"] == "ASMT-CONSOL-0001"
    print("build_report_json: OK ->", len(report_json), "fields")

    with open(TEMPLATE_PATH, "r") as f:
        template_str = f.read()

    markdown = render_markdown(
        template_str,
        report_id="ASMT-CONSOL-0001",
        generated_date="2026-07-12",
        t_code=fake_t_code,
        context=fake_context,
        narrative=fake_narrative,
        qa_result=fake_qa_result,
    )
    assert "T1558.001" in markdown
    assert "...and 12 more hosts (see JSON for full list)" in markdown
    assert "Critical: 3, High: 9, Medium: 2" in markdown
    print("render_markdown: OK ->", len(markdown), "chars")

    placeholder_names = _extract_placeholder_names(template_str)
    print(f"\nTemplate placeholder names ({len(placeholder_names)}):")
    for name in placeholder_names:
        print(f"  - {name}")

    print("\nSmoke test passed.")
````

---

### FILE: `assessment_template_consolidated.md` (sha256=0963452af09107f5b4dcc90e9f1ab60b82ce76826bfd0ce0a5ddd102cc6cf828)

````markdown
# Threat & Mitigation Assessment Report (Consolidated)

**Date:** {DATE}
**Assessment ID:** {ASSESSMENT_ID}
**Finding Count:** {FINDING_COUNT}
**Severity Breakdown:** {SEVERITY_BREAKDOWN}

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations. This report consolidates every host/finding pair below that resolved to the same ATT&CK technique — read it as one technique-level assessment covering multiple affected hosts, not a single-host report.*

**Finding / Threat Summary:** {THREAT_INPUT_SUMMARY}

**Affected Hosts:**

{AFFECTED_HOSTS_TABLE}

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact. This exploitation/impact analysis applies to every host in the table above — they all resolved to the same technique.*
- **Exploitation Scenario:** {EXPLOITATION_SCENARIO}
- **Potential Impact:** {BUSINESS_IMPACT}
- **Mission-Level Attribute at Risk (CSA):** {CSA_NAME} — {CSA_IMPACT_SUMMARY}

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique shared by all affected hosts.*
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

*Specific hardware, software, or configuration classes required to implement the ZIG capabilities and D3FEND countermeasures across all affected hosts.*

- **Recommended Technologies:**
  - {ZIG_TECHNOLOGY_1}
  - {ZIG_TECHNOLOGY_2}
- **Implementation Notes:** {TECHNOLOGY_IMPLEMENTATION_NOTES}

---

## 7. Plan of Action and Milestones (POA&M)

*Actionable steps for the engineering and security teams to resolve this technique-level gap. Each phase below applies across ALL affected hosts listed in Section 1 — remediation is tracked as one plan against the shared technique, not one plan per host.*

- [ ] **Phase 1 (Immediate):** {IMMEDIATE_ACTION}
- [ ] **Phase 2 (Short-Term):** {SHORT_TERM_ACTION}
- [ ] **Phase 3 (Long-Term/Strategic):** {LONG_TERM_ACTION}

---

## 8. QA/QC Review

*Automated quality-assurance pass over this report prior to human review. A FLAG verdict means a reviewer must check this report before it is treated as final; a PASS verdict means the automated checks found nothing amiss.*

- **QA Verdict:** {QA_VERDICT}
- **QA Notes:** {QA_NOTES}
````

---

### FILE: `run_analyst_pipeline.py` (sha256=9e90a129bf5aec4ff19d52447493f41387244a8c66f753169b309179bb2f348a)

````python
"""
run_analyst_pipeline.py

CLI entry point for the multi-provider, consolidated (many-hosts-per-technique)
analyst report pipeline. Wires together:

  scripts/consolidate_findings.py  -- groups CSV rows by ATT&CK technique and
                                       crawls the graph once per technique
  scripts/llm_providers.py         -- drafts narrative / proofreads / QA-reviews
                                       via a pluggable LLM provider (or the
                                       network-free heuristic fallback)
  scripts/report_schema.py         -- renders assessment_template_consolidated.md
                                       and builds the machine-readable JSON twin

Adapter note: consolidate_findings.build_context() and report_schema.py's
render_markdown()/build_report_json() were built independently and use
different field shapes for the same facts (e.g. lists vs. pre-joined display
strings, `finding_text` vs `finding`, a capped `affected_hosts` vs. the full
list expected for JSON). `_adapt_context_for_render()` and the full-host-list
override below reconcile those shapes; see their docstrings for specifics.
"""
import sys
import os
import re
import json
import argparse
from datetime import datetime

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))

from graph_engine import KnowledgeGraphEngine
from consolidate_findings import group_findings_by_technique, crawl_correlation, build_context
from llm_providers import get_provider
from report_schema import build_report_json, render_markdown

TEMPLATE_PATH = os.path.join(BASE_DIR, "assessment_template_consolidated.md")

# Matches bracketed framework-ID tokens the proofreader/QA pass might have
# touched: [T1234], [D3-XXX], [M1234], [ZIG-CAP-1.2], [CM1234], [AN1234], etc.
# The trailing negative lookahead excludes markdown link labels ([Persistence]
# (https://...)) -- ATT&CK's own technique descriptions embed these as
# citation-style cross-references, and without the exclusion every report
# containing one would be false-positive FLAGged as a hallucinated ID.
ID_TOKEN_RE = re.compile(r"\[([A-Z0-9][A-Za-z0-9.\-]*)\](?!\()")


def sanitize_report_id(t_code):
    """Filesystem-safe report id: CONSOL-<t_code> with '.'/':' replaced by '-'."""
    safe = t_code.replace('.', '-').replace(':', '-')
    return f"CONSOL-{safe}"


def _joined_or_default(items, default="None found in graph", sep=", "):
    return sep.join(items) if items else default


def _bulleted_or_default(items, default="None specified", limit=None):
    subset = items[:limit] if limit is not None else items
    if not subset:
        return default
    return "\n  - " + "\n  - ".join(subset)


def _adapt_context_for_render(context, narrative_fields):
    """Reshapes consolidate_findings' context into what report_schema.py expects.

    consolidate_findings.build_context() returns lists (`d3fend_countermeasures`,
    `mitre_analytics`, `zig_technologies`, `nist_controls`, ...) and a `zig_pillar`
    key, and its `affected_hosts` entries use `finding_text`. report_schema.py's
    render_markdown()/build_report_json() expect pre-joined display strings
    (`d3fend_countermeasure_1`, `mitre_analytics` as a bulleted block, ...),
    `zig_pillar_name`, and `affected_hosts` entries keyed by `finding`. This
    builds a new dict with both the original keys (untouched) and the adapted
    keys layered on top, plus the two narrative-authored fields
    (`csa_impact_summary`, `cref_recommendation`) that report_schema.py reads
    from context rather than from narrative.
    """
    adapted = dict(context)

    adapted["affected_hosts"] = [
        {**host, "finding": host.get("finding_text", host.get("finding", "N/A"))}
        for host in context.get("affected_hosts", [])
    ]

    d3fend_cms = context.get("d3fend_countermeasures") or []
    adapted["d3fend_countermeasure_1"] = d3fend_cms[0] if len(d3fend_cms) > 0 else "None found in graph"
    adapted["d3fend_countermeasure_2"] = d3fend_cms[1] if len(d3fend_cms) > 1 else "None found in graph"
    adapted["d3fend_artifacts"] = _joined_or_default((context.get("d3fend_artifacts") or [])[:3])

    adapted["mitre_analytics"] = _bulleted_or_default(context.get("mitre_analytics") or [], limit=2)
    adapted["mitre_mitigations"] = _bulleted_or_default(context.get("mitre_mitigations") or [], limit=2)

    adapted["zig_pillar_name"] = context.get("zig_pillar", "Unknown Pillar")
    adapted["zig_activity_1"] = f"[{context.get('zig_activity_id', 'None found')}] {context.get('zig_activity_name', 'No matching ZIG activity')}"

    zig_techs = context.get("zig_technologies") or []
    adapted["zig_technology_1"] = zig_techs[0] if len(zig_techs) > 0 else "None found in graph"
    adapted["zig_technology_2"] = zig_techs[1] if len(zig_techs) > 1 else "None found in graph"

    adapted["nist_800_53_controls"] = _joined_or_default(context.get("nist_controls") or [], default="None mapped in graph")

    # Narrative-authored fields report_schema.py reads off context, not narrative.
    adapted["csa_impact_summary"] = narrative_fields.get("csa_impact_summary", "")
    adapted["cref_recommendation"] = narrative_fields.get("architectural_recommendation", "")

    return adapted


def _build_render_narrative(t_code, context, provider_narrative, full_affected_hosts=None):
    """Builds the narrative dict render_markdown()/build_report_json() expect.

    llm_providers.LLMProvider.draft_narrative() returns 7 fields (NARRATIVE_KEYS);
    report_schema.py's renderer additionally needs `threat_input_summary` and
    `technology_implementation_notes`, neither of which the provider drafts --
    those are consolidated-report framing text, constructed here from context.

    `full_affected_hosts` (the uncapped list from group_data) is used for the
    unique-host count when supplied: `context["affected_hosts"]` is
    build_context()'s display-capped (<=50) list, so counting unique hostnames
    off of it alone would understate "N unique hosts" once a technique group
    exceeds the cap (e.g. "60 findings across 50 unique hosts" for 60 distinct
    hosts truncated for markdown display).
    """
    affected_hosts = context.get("affected_hosts", [])
    finding_count = context.get("finding_count", len(affected_hosts))
    hosts_for_unique_count = full_affected_hosts if full_affected_hosts is not None else affected_hosts
    unique_hosts = len({h.get("hostname") for h in hosts_for_unique_count}) if hosts_for_unique_count else 0
    threat_input_summary = (
        f"{finding_count} finding(s) across {unique_hosts} unique host(s) resolved to "
        f"[{t_code}] {context.get('technique_name', 'this technique')}."
    )

    return {
        "threat_input_summary": threat_input_summary,
        "exploitation_scenario": provider_narrative.get("exploitation_scenario", ""),
        "business_impact": provider_narrative.get("business_impact", ""),
        "immediate_action": provider_narrative.get("immediate_action", ""),
        "short_term_action": provider_narrative.get("short_term_action", ""),
        "long_term_action": provider_narrative.get("long_term_action", ""),
        "technology_implementation_notes": (
            "Ensure configurations align with vendor security baselines across all affected hosts."
        ),
    }


def find_unknown_ids(engine, markdown_text):
    """Deterministic hallucination safety net: every bracketed [ID] token in the
    proofread markdown must resolve to a real graph node. Returns the list of
    tokens that don't (proofreader/LLM hallucination candidates)."""
    tokens = sorted(set(ID_TOKEN_RE.findall(markdown_text)))
    unknown = [tok for tok in tokens if engine.query_node(tok) is None]
    return unknown


def _noop_progress(stage):
    pass


def run_pipeline(engine, input_csv, output_dir, provider_name=None, limit=None, progress_cb=None):
    """Consolidates findings by ATT&CK technique and generates multi-provider analyst reports.

    Does exactly what the CLI's former main() loop did (group by technique, crawl
    correlation, draft/proofread/QA via the provider, write .md + .json per group),
    but takes an already-constructed KnowledgeGraphEngine instead of building one
    (so a long-running caller can build the ~5600-node graph once and reuse it
    across many pipeline runs) and reports progress via progress_cb.

    Args:
        engine: an already-constructed KnowledgeGraphEngine.
        input_csv: path to the flattened findings CSV from ingest_assessment.py.
        output_dir: directory to write .md/.json reports into (created if missing).
        provider_name: passed through to get_provider() (None uses LLM_PROVIDER env var).
        limit: maximum number of technique groups to process (None processes all).
        progress_cb: optional callable(stage: str), invoked with a short
            human-readable stage name at each major step. Called once per stage
            per technique group (not per sub-step).

    Returns:
        A list of dicts, one per generated report:
        {"report_id":, "technique_id":, "technique_name":, "finding_count":,
         "severity_breakdown":, "qa_verdict":}.
    """
    progress_cb = progress_cb or _noop_progress
    generated_date = datetime.now().strftime('%Y-%m-%d')

    progress_cb("ingesting")
    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"Could not find {input_csv}. Did you run scripts/ingest_assessment.py first?")
        sys.exit(1)

    groups, skipped_count = group_findings_by_technique(engine, df)
    print(f"Skipped {skipped_count} row(s) with no technique resolution.")

    provider = get_provider(provider_name)
    print(f"Using provider: {type(provider).__name__}")

    os.makedirs(output_dir, exist_ok=True)

    with open(TEMPLATE_PATH, "r") as f:
        template_str = f.read()

    items = list(groups.items())
    if limit is not None:
        items = items[:limit]

    results = []

    for t_code, group_data in items:
        progress_cb("consolidating findings")
        correlation = crawl_correlation(engine, t_code)
        context = build_context(t_code, group_data, correlation)

        progress_cb("drafting narrative")
        provider_narrative = provider.draft_narrative(context)
        render_context = _adapt_context_for_render(context, provider_narrative)
        render_narrative = _build_render_narrative(
            t_code, render_context, provider_narrative,
            full_affected_hosts=group_data["affected_hosts"],
        )

        report_id = sanitize_report_id(t_code)

        draft_markdown = render_markdown(
            template_str, report_id, generated_date, t_code,
            render_context, render_narrative, {"verdict": "PENDING", "notes": ""},
        )

        progress_cb("proofreading")
        proofread_markdown = provider.proofread(draft_markdown)

        unknown_ids = find_unknown_ids(engine, proofread_markdown)

        progress_cb("qa review")
        qa_result = provider.qa_review(proofread_markdown, context)
        if unknown_ids:
            qa_result = dict(qa_result)
            qa_result["verdict"] = "FLAG"
            unknown_note = f"Unresolved framework ID(s) detected by deterministic check: {', '.join(unknown_ids)}."
            existing_notes = qa_result.get("notes") or ""
            qa_result["notes"] = f"{existing_notes} {unknown_note}".strip()

        # Swap in the real QA verdict/notes rather than the PENDING placeholder
        # the draft was rendered with. Regex substitution (rather than a full
        # re-render from the template) preserves any prose cleanup the
        # proofreader made to the rest of the document.
        # No required trailing space before `.*` -- the draft is rendered with an
        # empty notes field ("- **QA Notes:** " with nothing after the space), and
        # a proofreading pass will often strip that "orphan" trailing whitespace,
        # which silently breaks a pattern that requires the space literally (re.sub
        # finds zero matches and returns the string unchanged with no error).
        final_markdown = re.sub(
            r"- \*\*QA Verdict:\*\*.*",
            f"- **QA Verdict:** {qa_result['verdict']}",
            proofread_markdown,
            count=1,
        )
        final_markdown = re.sub(
            r"- \*\*QA Notes:\*\*.*",
            f"- **QA Notes:** {qa_result['notes']}",
            final_markdown,
            count=1,
        )

        progress_cb("writing reports")
        md_path = os.path.join(output_dir, f"{report_id}.md")
        with open(md_path, "w") as f:
            f.write(final_markdown)
        # Reports are bind-mounted into the host filesystem specifically so a
        # human can open/edit them with a normal text editor (see
        # docker-compose.yml). When this runs inside the web UI's Docker
        # container (as root), the default 0644 the container's umask
        # produces leaves the file owned by root:root and unwritable by the
        # host user. chmod to world-writable so the host user (unknown UID
        # inside the container) can still edit/delete it without sudo. Cheap
        # no-op on the plain-CLI/air-gapped path, where the file is already
        # owned by the invoking user.
        os.chmod(md_path, 0o666)

        report_json = build_report_json(t_code, render_context, render_narrative, qa_result)
        report_json["report_id"] = report_id
        report_json["generated_date"] = generated_date
        # build_report_json's affected_hosts should be the FULL list for machine
        # consumption; build_context() already capped it for markdown display.
        report_json["affected_hosts"] = [
            {**host, "finding": host.get("finding_text", host.get("finding", "N/A"))}
            for host in group_data["affected_hosts"]
        ]
        report_json["finding_count"] = len(report_json["affected_hosts"])

        json_path = os.path.join(output_dir, f"{report_id}.json")
        with open(json_path, "w") as f:
            json.dump(report_json, f, indent=2)
        os.chmod(json_path, 0o666)  # see chmod comment on md_path above

        print(f"Generated {report_id}: {context['finding_count']} findings consolidated, QA={qa_result['verdict']}")

        results.append({
            "report_id": report_id,
            "technique_id": t_code,
            "technique_name": context.get("technique_name"),
            "finding_count": report_json["finding_count"],
            "severity_breakdown": group_data["severity_breakdown"],
            "qa_verdict": qa_result["verdict"],
        })

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Consolidate findings by ATT&CK technique and generate multi-provider analyst reports"
    )
    parser.add_argument("--input", default="processed_assessment.csv", help="Flattened findings CSV from ingest_assessment.py")
    parser.add_argument("--output-dir", default="reports", help="Directory to write .md/.json reports into")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of technique groups to process (default: all)")
    parser.add_argument("--provider", default=None, help="Override the LLM_PROVIDER env var (local/openai/gemini/none)")
    args = parser.parse_args()

    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()

    run_pipeline(engine, args.input, args.output_dir, provider_name=args.provider, limit=args.limit)


if __name__ == "__main__":
    main()
````


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
tokens = sorted(set(re.findall(r'\[([A-Z0-9][A-Za-z0-9.\-]*)\](?!\()', md)))
unknown = [t for t in tokens if e.query_node(t) is None]
print(f'{len(tokens)} bracketed IDs found, {len(unknown)} unresolved:', unknown)
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
