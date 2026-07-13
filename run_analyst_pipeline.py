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
import hashlib
import tempfile
from datetime import datetime
from time import perf_counter

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))

from graph_engine import KnowledgeGraphEngine
from consolidate_findings import group_findings_by_technique, crawl_correlation, build_context
from llm_providers import ProviderOperationCanceled, get_provider
from llm_graph_tools import GraphToolSession, ToolPolicy
from report_schema import build_report_json, render_markdown, _is_hostless

TEMPLATE_PATH = os.path.join(BASE_DIR, "assessment_template_consolidated.md")

# Matches bracketed framework-ID tokens the proofreader/QA pass might have
# touched: [T1234], [D3-XXX], [M1234], [ZIG-CAP-1.2], [CM1234], [AN1234], etc.
# The trailing negative lookahead excludes markdown link labels ([Persistence]
# (https://...)) -- ATT&CK's own technique descriptions embed these as
# citation-style cross-references, and without the exclusion every report
# containing one would be false-positive FLAGged as a hallucinated ID.
ID_TOKEN_RE = re.compile(r"\[([A-Z0-9][A-Za-z0-9.\-]*)\](?!\()")
DISPLAY_MAPPING_LIMIT = 12
MODEL_MAPPING_ITEM_LIMIT = 12
MODEL_OBSERVATION_EXCERPT_LIMIT = 1_200
MODEL_QA_MARKDOWN_MAX_CHARS = max(4_000, int(os.environ.get("LLM_QA_MARKDOWN_MAX_CHARS", "40_000")))


def sanitize_report_id(t_code):
    """Filesystem-safe report id: CONSOL-<t_code> with '.'/':' replaced by '-'."""
    safe = t_code.replace('.', '-').replace(':', '-')
    return f"CONSOL-{safe}"


def _unique_nonempty(items):
    """Stable de-duplication for graph summaries and Markdown presentation."""
    return list(dict.fromkeys(str(item) for item in items if item not in (None, "")))


def _joined_or_default(items, default="None found in graph", sep=", ", limit=None):
    values = _unique_nonempty(items)
    if not values:
        return default
    subset = values[:limit] if limit is not None else values
    text = sep.join(subset)
    if limit is not None and len(values) > len(subset):
        text += f"{sep}… and {len(values) - len(subset)} more (see JSON/API)"
    return text


def _bulleted_or_default(items, default="None specified", limit=None):
    values = _unique_nonempty(items)
    subset = values[:limit] if limit is not None else values
    if not subset:
        return default
    rendered = "\n  - " + "\n  - ".join(subset)
    if limit is not None and len(values) > len(subset):
        rendered += f"\n  - … and {len(values) - len(subset)} more (see JSON/API)"
    return rendered


def _graph_label(item_id, name, default="None found in graph"):
    if not item_id:
        return default
    return f"[{item_id}] {name or item_id}"


def _mapping_label(item, item_id_key, item_name_key, default="None found in graph"):
    """Render one validated mapping without concealing inherited provenance."""
    label = _graph_label(item.get(item_id_key), item.get(item_name_key), default)
    if item.get("mapping_scope") == "inherited_parent":
        return f"{label} (inherited from parent technique)"
    return label


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

    mappings = context.get("framework_mappings") or {}
    zig_mappings = mappings.get("zig") or []
    cref_mappings = mappings.get("cref") or []
    # ``mitigations`` includes both CREF mitigation nodes and native ATT&CK
    # M#### nodes.  The old ``cref_mitigations``-only display silently hid the
    # latter even though their paths carry CREF/NIST/ZIG relationships.
    mitigation_mappings = mappings.get("mitigations") or mappings.get("cref_mitigations") or []
    csa_mappings = mappings.get("csa") or []

    if zig_mappings:
        adapted["zig_pillar_name"] = _joined_or_default(
            [_mapping_label(item, "pillar_id", "pillar_name", "Unknown Pillar") for item in zig_mappings],
            default="Unknown Pillar", limit=DISPLAY_MAPPING_LIMIT,
        )
        adapted["zig_capability_id"] = _joined_or_default(
            [item.get("capability_id") or "None found" for item in zig_mappings],
            default="None found", limit=DISPLAY_MAPPING_LIMIT,
        )
        adapted["zig_capability_name"] = _joined_or_default(
            [_mapping_label(item, "capability_id", "capability_name", "No matching ZIG capability") for item in zig_mappings],
            default="No matching ZIG capability", limit=DISPLAY_MAPPING_LIMIT,
        )
        adapted["zig_activity_1"] = _bulleted_or_default([
            _mapping_label(item, "activity_id", "activity_name")
            for item in zig_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
    else:
        adapted["zig_pillar_name"] = context.get("zig_pillar", "Unknown Pillar")
        adapted["zig_activity_1"] = _graph_label(
            context.get("zig_activity_id"), context.get("zig_activity_name"),
            "No matching ZIG activity",
        )

    if cref_mappings:
        adapted["cref_goal"] = _bulleted_or_default([
            _mapping_label(item, "goal_id", "goal_name") for item in cref_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
        adapted["cref_objective"] = _bulleted_or_default([
            _mapping_label(item, "objective_id", "objective_name") for item in cref_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
        adapted["cref_technique"] = _bulleted_or_default([
            _mapping_label(item, "technique_id", "technique_name") for item in cref_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
        adapted["cref_approach"] = _bulleted_or_default([
            _mapping_label(item, "approach_id", "approach_name") for item in cref_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
        adapted["cref_effect"] = _bulleted_or_default([
            _mapping_label(item, "effect_id", "effect_name") for item in cref_mappings
        ], limit=DISPLAY_MAPPING_LIMIT)
    if mitigation_mappings:
        adapted["cref_mitigation_id"] = _joined_or_default(
            [item.get("mitigation_id") for item in mitigation_mappings], limit=DISPLAY_MAPPING_LIMIT
        )
        adapted["cref_mitigation_name"] = _joined_or_default(
            [_mapping_label(item, "mitigation_id", "mitigation_name") for item in mitigation_mappings],
            limit=DISPLAY_MAPPING_LIMIT,
        )
        controls = _unique_nonempty(
            control for item in mitigation_mappings for control in item.get("nist_800_53_controls", [])
        )
        adapted["nist_800_53_controls"] = _joined_or_default(
            controls, default="None mapped in graph", limit=DISPLAY_MAPPING_LIMIT
        )
        adapted["traceability"] = _joined_or_default([
            f"Implements ZIG Activity {activity_id}"
            for item in mitigation_mappings for activity_id in item.get("zig_activity_ids", [])
        ], default=context.get("traceability", "N/A — no graph mapping"), limit=DISPLAY_MAPPING_LIMIT)
    if csa_mappings:
        adapted["csa_name"] = _joined_or_default(
            [_mapping_label(item, "csa_id", "csa_name") for item in csa_mappings],
            limit=DISPLAY_MAPPING_LIMIT,
        )

    zig_techs = context.get("zig_technologies") or []
    adapted["zig_technology_1"] = zig_techs[0] if len(zig_techs) > 0 else "None found in graph"
    adapted["zig_technology_2"] = zig_techs[1] if len(zig_techs) > 1 else "None found in graph"

    adapted.setdefault("nist_800_53_controls", _joined_or_default(context.get("nist_controls") or [], default="None mapped in graph"))

    # Narrative-authored fields report_schema.py reads off context, not narrative.
    adapted["csa_impact_summary"] = narrative_fields.get("csa_impact_summary", "")
    adapted["cref_recommendation"] = narrative_fields.get("architectural_recommendation", "")

    return adapted


def _compact_mapping_value(value, *, item_limit=MODEL_MAPPING_ITEM_LIMIT):
    """Keep model prompts bounded without dropping the authoritative bundle.

    The complete mapping paths remain in ``context['framework_mappings']`` and
    in the report JSON.  This function produces a presentation/reasoning view
    for a provider: IDs, names, scope, counts, and a deterministic sample, but
    never thousands of repetitive path IDs or edge objects.
    """
    if isinstance(value, list):
        compacted = [_compact_mapping_value(item, item_limit=item_limit) for item in value[:item_limit]]
        if len(value) > item_limit:
            compacted.append({"_omitted_items": len(value) - item_limit, "_note": "Full validated data is retained outside the model prompt."})
        return compacted
    if isinstance(value, dict):
        excluded = {"paths", "path_ids", "edges", "nodes"}
        compacted = {
            key: _compact_mapping_value(item, item_limit=item_limit)
            for key, item in value.items()
            if key not in excluded
        }
        if "path_ids" in value:
            compacted["path_count"] = len(value.get("path_ids") or [])
        return compacted
    return value


def _llm_context(context):
    """Produce a bounded, explicitly untrusted-input view for an LLM call."""
    compact = {key: value for key, value in context.items() if key not in {"framework_mappings", "affected_hosts"}}
    observations = []
    for host in (context.get("affected_hosts") or [])[:MODEL_MAPPING_ITEM_LIMIT]:
        item = dict(host)
        source = str(item.get("finding_text", item.get("finding", "")))
        if len(source) > MODEL_OBSERVATION_EXCERPT_LIMIT:
            item["finding_text"] = source[:MODEL_OBSERVATION_EXCERPT_LIMIT]
            item["source_excerpt_truncated"] = True
            item["source_excerpt_range"] = [0, MODEL_OBSERVATION_EXCERPT_LIMIT]
        observations.append(item)
    compact["affected_hosts"] = observations
    if len(context.get("affected_hosts") or []) > len(observations):
        compact["affected_hosts_omitted"] = len(context["affected_hosts"]) - len(observations)

    bundle = context.get("framework_mappings") or {}
    categories = (
        "attack_tactics", "zig", "cref", "mitigations", "attack_mitigations",
        "cref_mitigations", "csa", "d3fend", "analytics",
    )
    compact_bundle = {
        "graph_snapshot_id": bundle.get("graph_snapshot_id"),
        "mapping_matrix_version": bundle.get("mapping_matrix_version"),
        "mapping_validation": bundle.get("mapping_validation"),
        "inheritance": bundle.get("inheritance", []),
        "not_mapped_categories": bundle.get("not_mapped_categories", []),
        "path_count": len(bundle.get("paths") or []),
    }
    for category in categories:
        entries = bundle.get(category) or []
        compact_bundle[f"{category}_count"] = len(entries)
        compact_bundle[category] = _compact_mapping_value(entries)
    compact["framework_mappings"] = compact_bundle
    return compact


def _qa_model_markdown(markdown_text):
    """Bound untrusted report content before a provider QA request.

    Rendered Markdown is retained in full as the immutable report artifact;
    this only limits evidence/prose copied into a local/cloud model context.
    The deterministic mapping and identifier checks still operate on the full
    report after rendering.
    """
    if len(markdown_text) <= MODEL_QA_MARKDOWN_MAX_CHARS:
        return markdown_text
    return (
        markdown_text[:MODEL_QA_MARKDOWN_MAX_CHARS]
        + "\n\n[MODEL INPUT TRUNCATED: the full immutable report remains available to reviewers; do not infer facts beyond this excerpt.]\n"
    )


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

    if _is_hostless(hosts_for_unique_count):
        # CTI/adversary-narrative input carries no real asset data -- "N unique
        # host(s)" would be a meaningless "N/A" count, so drop the host framing
        # entirely rather than report a number that implies asset context that
        # was never there.
        threat_input_summary = (
            f"{finding_count} observation(s) resolved to "
            f"[{t_code}] {context.get('technique_name', 'this technique')}."
        )
    else:
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


class PipelineCanceled(RuntimeError):
    """Raised at a cooperative checkpoint when a durable run is canceled."""


def _emit_progress(progress_cb, event):
    """Deliver rich progress while remaining compatible with legacy callbacks."""
    try:
        progress_cb(event)
    except TypeError:
        progress_cb(event.get("phase", event.get("stage", "running")))


def _atomic_write(path, content, *, binary=False):
    """Publish report artifacts atomically so readers never see partial JSON/MD."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    mode = "wb" if binary else "w"
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
    try:
        with os.fdopen(fd, mode, encoding=None if binary else "utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _context_graph_ids(context):
    """Return graph identifiers deliberately retrieved for this report.

    LLM prose may not introduce an arbitrary real graph ID. This set is built
    from the validated mapping bundle and legacy deterministic context fields.
    """
    ids = {str(context.get("technique_id", ""))}

    def walk(value, key=None):
        if isinstance(value, dict):
            for child_key, child in value.items():
                if child_key.endswith("_id") and isinstance(child, str):
                    ids.add(child)
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child, key)
        elif isinstance(value, str):
            ids.update(ID_TOKEN_RE.findall(value))

    walk(context.get("framework_mappings", {}))
    for key, value in context.items():
        if key not in {"affected_hosts", "framework_mappings"}:
            walk(value, key)
    ids.discard("")
    return ids


def find_disallowed_narrative_ids(engine, narrative, context):
    """IDs mentioned by the LLM must be in the retrieved, validated bundle."""
    tokens = sorted(set(ID_TOKEN_RE.findall(json.dumps(narrative, default=str))))
    allowed = _context_graph_ids(context)
    return [token for token in tokens if engine.query_node(token) is None or token not in allowed]


def _report_lifecycle(qa_result, provider_status):
    verdict = qa_result.get("verdict", "FLAG")
    if verdict == "PASS" and not provider_status.get("degraded"):
        return "auto_passed", False
    if verdict == "PASS":
        return "manual_review_required", True
    if verdict == "NOT_EVALUATED":
        return "manual_review_required", True
    return "auto_flagged", True


def _should_run_graph_tools(provider):
    """Only real local/cloud model providers may claim to crawl graph tools."""
    configured = os.environ.get("LLM_GRAPH_TOOL_CRAWL", "enabled").strip().lower()
    if configured in {"0", "false", "off", "disabled", "no"}:
        return False
    return provider.status.get("effective_provider") not in {"heuristic", "none", ""}


def run_pipeline(
    engine,
    input_csv,
    output_dir,
    provider_name=None,
    limit=None,
    progress_cb=None,
    cancel_cb=None,
    report_id_factory=None,
    run_id=None,
):
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
        progress_cb: optional callback accepting a structured progress event
            (legacy string callbacks remain supported).
        cancel_cb: optional cooperative cancellation predicate.
        report_id_factory: optional callable `(technique_id, ordinal) -> id`.
            Web runs should use persistent UUID identities; the legacy
            `CONSOL-Txxxx` value remains the CLI default display key.
        run_id: optional durable run identifier included in results/events.

    Returns:
        A list of dicts, one per generated report:
        {"report_id":, "technique_id":, "technique_name":, "finding_count":,
         "severity_breakdown":, "qa_verdict":}.
    """
    progress_cb = progress_cb or _noop_progress
    cancel_cb = cancel_cb or (lambda: False)
    generated_date = datetime.now().strftime('%Y-%m-%d')

    _emit_progress(progress_cb, {
        "type": "run_started", "phase": "ingesting", "message": "Loading normalized observations",
        "current": {}, "counters": {}, "metrics": {}, "run_id": run_id,
    })
    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        raise FileNotFoundError(f"Normalized input does not exist: {input_csv}")
    if df.empty:
        raise ValueError("Normalized input contains no observations.")

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

    total = len(items)
    _emit_progress(progress_cb, {
        "type": "mapping_grouped", "phase": "mapping", "message": "Resolved observations into ATT&CK technique groups",
        "current": {},
        "counters": {
            "observations_total": len(df), "observations_completed": len(df),
            "observations_unresolved": skipped_count, "techniques_total": total,
            "techniques_completed": 0, "reports_total": total, "reports_completed": 0,
            "reports_auto_passed": 0, "reports_flagged": 0, "reports_review_pending": 0,
        },
        "metrics": {}, "run_id": run_id,
    })

    results = []

    for ordinal, (t_code, group_data) in enumerate(items, start=1):
        if cancel_cb():
            raise PipelineCanceled("Run canceled before completing all technique groups.")

        counters = {
            "observations_total": len(df), "observations_completed": len(df),
            "observations_unresolved": skipped_count, "techniques_total": total,
            "techniques_completed": ordinal - 1, "reports_total": total,
            "reports_completed": len(results),
            "reports_auto_passed": sum(r.get("lifecycle_state") == "auto_passed" for r in results),
            "reports_flagged": sum(r.get("lifecycle_state") == "auto_flagged" for r in results),
            "reports_review_pending": sum(r.get("requires_review") for r in results),
        }
        _emit_progress(progress_cb, {
            "type": "technique_started", "phase": "graph_mapping",
            "message": f"Building validated graph mappings for {t_code}",
            "current": {"technique_id": t_code, "report_key": sanitize_report_id(t_code)},
            "counters": counters, "metrics": {}, "run_id": run_id,
        })
        correlation = crawl_correlation(engine, t_code)
        context = build_context(t_code, group_data, correlation)

        bundle = context.get("framework_mappings") or {}
        path_count = len(bundle.get("paths", [])) if isinstance(bundle, dict) else 0

        _emit_progress(progress_cb, {
            "type": "graph_mapping_finished", "phase": "drafting_narrative",
            "message": f"Validated {path_count} graph paths for {t_code}",
            "current": {"technique_id": t_code}, "counters": counters,
            "metrics": {"path_count": path_count}, "run_id": run_id,
        })
        model_context = _llm_context(context)
        graph_tool_crawl = {
            "status": "not_evaluated",
            "reason": "No configured local/cloud model was available for graph tool planning.",
            "selected": [],
            "audit": {"calls": []},
        }
        provider_call_metrics = {"token_usage_available": False}
        if _should_run_graph_tools(provider):
            _emit_progress(progress_cb, {
                "type": "llm_graph_tool_started", "phase": "llm_graph_crawl",
                "message": f"Starting bounded read-only graph tool crawl for {t_code}",
                "current": {"technique_id": t_code}, "counters": counters,
                "metrics": {}, "run_id": run_id,
            })
            tool_session = GraphToolSession(engine, policy=ToolPolicy())
            graph_tool_started = perf_counter()
            def graph_tool_progress(event):
                # Provider calls are synchronous, but this callback gives the
                # durable event stream a heartbeat before and after every
                # bounded request and immediately observes user cancellation.
                if cancel_cb():
                    raise PipelineCanceled("Run canceled during bounded graph-tool crawl.")
                event_type = str(event.get("type") or "provider_progress")
                action = str(event.get("action") or "")
                request_index = event.get("request_index")
                request_total = event.get("request_total")
                if event_type == "provider_request_started":
                    message = f"LLM graph planner request {request_index} of {request_total} for {t_code}"
                elif event_type == "provider_request_finished":
                    message = f"LLM graph planner response {request_index} of {request_total} received for {t_code}"
                elif event_type == "provider_request_failed":
                    message = f"LLM graph planner request {request_index} failed for {t_code}"
                elif event_type == "tool_executed":
                    message = f"Graph tool: {action or 'unknown'}"
                else:
                    message = f"LLM graph crawl progress for {t_code}"
                metrics = {
                    key: event[key]
                    for key in ("request_index", "request_total", "latency_ms", "remaining_tool_calls")
                    if event.get(key) is not None
                }
                _emit_progress(progress_cb, {
                    "type": f"llm_graph_tool_{event_type}",
                    "phase": "llm_graph_crawl",
                    "message": message,
                    "current": {"technique_id": t_code},
                    "counters": counters,
                    "metrics": metrics,
                    "tool_call": event.get("tool_call"),
                    "run_id": run_id,
                })
            try:
                graph_tool_crawl = provider.crawl_graph(
                    tool_session,
                    model_context,
                    cancel_cb=cancel_cb,
                    progress_cb=graph_tool_progress,
                )
            except ProviderOperationCanceled as exc:
                raise PipelineCanceled(str(exc)) from exc
            provider_call_metrics["graph_tool_crawl_latency_ms"] = round((perf_counter() - graph_tool_started) * 1000, 1)
            for call in graph_tool_crawl.get("audit", {}).get("calls", []):
                _emit_progress(progress_cb, {
                    "type": "llm_graph_tool_call", "phase": "llm_graph_crawl",
                    "message": f"Graph tool: {call.get('action', 'unknown')}",
                    "current": {"technique_id": t_code}, "counters": counters,
                    "metrics": {"tool_call_sequence": call.get("sequence", 0)},
                    "tool_call": call, "run_id": run_id,
                })
            _emit_progress(progress_cb, {
                "type": "llm_graph_tool_finished", "phase": "drafting_narrative",
                "message": f"Bounded graph tool crawl {graph_tool_crawl.get('status', 'finished')} for {t_code}",
                "current": {"technique_id": t_code}, "counters": counters,
                "metrics": {
                    "tool_calls": len(graph_tool_crawl.get("audit", {}).get("calls", [])),
                    "provider_latency_ms": provider_call_metrics["graph_tool_crawl_latency_ms"],
                },
                "run_id": run_id,
            })

        # Graph tools may assist candidate selection, but never replace the
        # deterministic selected TTP.  A valid-yet-unretrieved alternate ID is
        # treated as a reviewable mismatch, not silently adopted.
        selected_ids = {str(item.get("id")) for item in graph_tool_crawl.get("selected", []) if item.get("id")}
        graph_tool_mismatch = bool(selected_ids and selected_ids != {t_code})
        graph_tool_required = _should_run_graph_tools(provider)
        graph_tool_unverified = graph_tool_required and graph_tool_crawl.get("status") != "validated"
        if cancel_cb():
            raise PipelineCanceled("Run canceled before narrative drafting.")
        _emit_progress(progress_cb, {
            "type": "llm_narrative_started", "phase": "drafting_narrative",
            "message": f"Drafting analyst narrative for {t_code}",
            "current": {"technique_id": t_code}, "counters": counters,
            "metrics": {}, "run_id": run_id,
        })
        narrative_started = perf_counter()
        provider_narrative = provider.draft_narrative(model_context)
        provider_call_metrics["narrative_latency_ms"] = round((perf_counter() - narrative_started) * 1000, 1)
        if cancel_cb():
            raise PipelineCanceled("Run canceled after narrative drafting.")
        _emit_progress(progress_cb, {
            "type": "llm_narrative_finished", "phase": "drafting_narrative",
            "message": f"Narrative draft completed for {t_code}",
            "current": {"technique_id": t_code}, "counters": counters,
            "metrics": {"provider_latency_ms": provider_call_metrics["narrative_latency_ms"]}, "run_id": run_id,
        })
        render_context = _adapt_context_for_render(context, provider_narrative)
        render_narrative = _build_render_narrative(
            t_code, render_context, provider_narrative,
            full_affected_hosts=group_data["affected_hosts"],
        )

        report_id = report_id_factory(t_code, ordinal) if report_id_factory else sanitize_report_id(t_code)

        draft_markdown = render_markdown(
            template_str, report_id, generated_date, t_code,
            render_context, render_narrative, {"verdict": "PENDING", "notes": ""},
        )

        # Graph-backed Markdown is server-rendered and immutable. Do not send
        # it to a proofreader that could alter factual mapping sections.
        final_markdown = draft_markdown

        _emit_progress(progress_cb, {
            "type": "qa_started", "phase": "qa_review", "message": f"Reviewing {t_code}",
            "current": {"technique_id": t_code}, "counters": counters, "metrics": {}, "run_id": run_id,
        })
        if cancel_cb():
            raise PipelineCanceled("Run canceled before QA review.")
        qa_started = perf_counter()
        qa_result = provider.qa_review(_qa_model_markdown(final_markdown), model_context)
        provider_call_metrics["qa_latency_ms"] = round((perf_counter() - qa_started) * 1000, 1)
        if cancel_cb():
            raise PipelineCanceled("Run canceled after QA review.")
        _emit_progress(progress_cb, {
            "type": "qa_finished", "phase": "qa_review", "message": f"QA completed for {t_code}",
            "current": {"technique_id": t_code}, "counters": counters,
            "metrics": {"provider_latency_ms": provider_call_metrics["qa_latency_ms"]}, "run_id": run_id,
        })
        disallowed_ids = find_disallowed_narrative_ids(engine, provider_narrative, context)
        if disallowed_ids:
            qa_result = dict(qa_result)
            qa_result["verdict"] = "FLAG"
            unknown_note = (
                "Framework ID(s) in model-authored narrative were not part of the "
                f"validated mapping bundle: {', '.join(disallowed_ids)}."
            )
            existing_notes = qa_result.get("notes") or ""
            qa_result["notes"] = f"{existing_notes} {unknown_note}".strip()
        if graph_tool_mismatch:
            qa_result = dict(qa_result)
            qa_result["verdict"] = "FLAG"
            mismatch_note = (
                "Bounded LLM graph-tool selection did not validate exactly the deterministic "
                f"technique {t_code}; selected: {', '.join(sorted(selected_ids))}."
            )
            qa_result["notes"] = f"{qa_result.get('notes', '')} {mismatch_note}".strip()

        provider_status = provider.status
        lifecycle_state, requires_review = _report_lifecycle(qa_result, provider_status)
        low_confidence_mapping = bool(group_data.get("requires_review"))
        inherited_mapping = any(
            isinstance(path, dict) and path.get("mapping_scope") == "inherited_parent"
            for path in (context.get("framework_mappings") or {}).get("paths", [])
        )
        if low_confidence_mapping:
            # The graph facts are still validated, but a semantic candidate is
            # lower-confidence source attribution.  It may never silently
            # become an automatically accepted report.
            if lifecycle_state == "auto_passed":
                lifecycle_state = "manual_review_required"
            requires_review = True
            qa_result = dict(qa_result)
            note = "At least one source observation used a score/margin-qualified semantic technique candidate; human review is required."
            qa_result["notes"] = f"{qa_result.get('notes', '')} {note}".strip()
        if inherited_mapping:
            if lifecycle_state == "auto_passed":
                lifecycle_state = "manual_review_required"
            requires_review = True
            qa_result = dict(qa_result)
            note = "Framework mappings inherit from a parent ATT&CK technique and require human scope review."
            qa_result["notes"] = f"{qa_result.get('notes', '')} {note}".strip()
        if graph_tool_unverified:
            # A configured model that fails to complete the constrained
            # inspection loop cannot turn a deterministic mapping into an
            # automatic acceptance.  The graph facts remain available, but a
            # reviewer must decide whether the provider failure is material.
            if lifecycle_state == "auto_passed":
                lifecycle_state = "manual_review_required"
            requires_review = True
            qa_result = dict(qa_result)
            note = (
                "Configured LLM graph-tool crawl did not complete deterministic selection validation "
                f"(status: {graph_tool_crawl.get('status', 'unknown')}); human review is required."
            )
            qa_result["notes"] = f"{qa_result.get('notes', '')} {note}".strip()
        final_markdown = re.sub(r"- \*\*QA Verdict:\*\*.*", f"- **QA Verdict:** {qa_result['verdict']}", final_markdown, count=1)
        final_markdown = re.sub(r"- \*\*QA Notes:\*\*.*", f"- **QA Notes:** {qa_result['notes']}", final_markdown, count=1)

        _emit_progress(progress_cb, {
            "type": "report_writing", "phase": "writing_reports", "message": f"Writing {report_id}",
            "current": {"technique_id": t_code, "report_key": report_id}, "counters": counters,
            "metrics": {}, "run_id": run_id,
        })
        md_path = os.path.join(output_dir, f"{report_id}.md")
        _atomic_write(md_path, final_markdown)

        report_json = build_report_json(t_code, render_context, render_narrative, qa_result)
        report_json["report_id"] = report_id
        report_json["generated_date"] = generated_date
        report_json["schema_version"] = "2.0"
        report_json["pipeline_version"] = "evidence-first"
        report_json["run_id"] = run_id
        report_json["lifecycle_state"] = lifecycle_state
        report_json["requires_review"] = requires_review
        report_json["mapping_confidence"] = {
            "requires_review": requires_review,
            "semantic_candidate_present": low_confidence_mapping,
            "inherited_parent_mapping_present": inherited_mapping,
        }
        report_json["provider"] = provider_status
        report_json["llm_graph_tool_crawl"] = graph_tool_crawl
        report_json["llm_graph_tool_validation_required"] = graph_tool_required
        report_json["model_input_policy"] = {
            "observation_excerpt_max_characters": MODEL_OBSERVATION_EXCERPT_LIMIT,
            "observation_item_limit": MODEL_MAPPING_ITEM_LIMIT,
            "qa_markdown_max_characters": MODEL_QA_MARKDOWN_MAX_CHARS,
        }
        report_json["provider_call_metrics"] = provider_call_metrics
        report_json["mapping_snapshot_hash"] = hashlib.sha256(
            json.dumps(context.get("framework_mappings", {}), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        # build_report_json's affected_hosts should be the FULL list for machine
        # consumption; build_context() already capped it for markdown display.
        report_json["affected_hosts"] = [
            {**host, "finding": host.get("finding_text", host.get("finding", "N/A"))}
            for host in group_data["affected_hosts"]
        ]
        report_json["finding_count"] = len(report_json["affected_hosts"])

        json_path = os.path.join(output_dir, f"{report_id}.json")
        _atomic_write(json_path, json.dumps(report_json, indent=2))

        print(f"Generated {report_id}: {context['finding_count']} findings consolidated, QA={qa_result['verdict']}")

        result = {
            "report_id": report_id,
            "report_key": sanitize_report_id(t_code),
            "technique_id": t_code,
            "technique_name": context.get("technique_name"),
            "finding_count": report_json["finding_count"],
            "severity_breakdown": group_data["severity_breakdown"],
            "qa_verdict": qa_result["verdict"],
            "lifecycle_state": lifecycle_state,
            "requires_review": requires_review,
            "markdown_path": md_path,
            "json_path": json_path,
            "mapping_snapshot_hash": report_json["mapping_snapshot_hash"],
            "framework_mappings": context.get("framework_mappings", {}),
            "observations": report_json["affected_hosts"],
            "provider": provider_status,
            "provider_call_metrics": provider_call_metrics,
            "narrative": provider_narrative,
            "llm_graph_tool_crawl": graph_tool_crawl,
        }
        results.append(result)
        counters["techniques_completed"] = ordinal
        counters["reports_completed"] = len(results)
        counters["reports_auto_passed"] = sum(r.get("lifecycle_state") == "auto_passed" for r in results)
        counters["reports_flagged"] = sum(r.get("lifecycle_state") == "auto_flagged" for r in results)
        counters["reports_review_pending"] = sum(r.get("requires_review") for r in results)
        _emit_progress(progress_cb, {
            "type": "report_finished", "phase": "writing_reports", "message": f"Generated {report_id}",
            "current": {"technique_id": t_code, "report_key": report_id}, "counters": counters,
            "metrics": {}, "result": result, "run_id": run_id,
        })

    _emit_progress(progress_cb, {
        "type": "analysis_finished", "phase": "analysis_finished",
        "message": "All technique groups generated; review gate will determine completion.",
        "current": {}, "counters": counters if items else {"reports_total": 0, "reports_completed": 0},
        "metrics": {}, "run_id": run_id,
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
