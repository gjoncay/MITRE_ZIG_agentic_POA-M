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
