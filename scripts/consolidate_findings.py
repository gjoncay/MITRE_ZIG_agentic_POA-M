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
import re
import sys
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))
from graph_engine import KnowledgeGraphEngine

# Matches a literal ATT&CK technique ID mentioned anywhere in a row's text, e.g.
# "T1566" or "T1078.004". Word boundaries keep this from matching inside a
# longer alphanumeric token.
TECHNIQUE_ID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)
SEMANTIC_MIN_SCORE = float(os.environ.get("CSDH_SEMANTIC_MIN_SCORE", "0.28"))
SEMANTIC_MIN_MARGIN = float(os.environ.get("CSDH_SEMANTIC_MIN_MARGIN", "0.05"))


def first_present(row, candidates, default="Unknown"):
    """Returns the first non-empty value among candidate column names (schemas vary per team)."""
    for col in candidates:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return default


def compose_finding_text(row, candidates):
    """Descriptive text for a row: the first matching named candidate column,
    or -- if none of those columns exist -- every non-empty column joined
    together. Without this fallback, a row from an unfamiliar schema (e.g. a
    MITRE ATT&CK group's own "techniques used" export, whose columns are
    ID/Name/Tactics rather than Finding/Observation/Description) degrades to
    the literal string "Unknown" for every row, which is useless as a
    semantic-search query and as a compose_finding_text fallback everywhere
    else it's shown (e.g. the Affected Hosts table's Finding column).
    """
    named = first_present(row, candidates, default=None)
    if named:
        return named
    parts = [
        f"{col}: {str(val).strip()}" for col, val in row.items()
        # Run/sheet provenance is retained in underscore-prefixed columns but
        # is not behavior evidence.  Searching it can map every row in a sheet
        # because one technique happened to appear in an administrative title.
        if not str(col).startswith('_') and pd.notna(val) and str(val).strip() and str(val).strip().lower() != 'nan'
    ]
    return " | ".join(parts) if parts else "Unknown"


def extract_direct_technique_ids(engine, text):
    """Finds literal ATT&CK technique IDs mentioned directly in text (e.g. a
    MITRE ATT&CK Navigator/group "techniques used" export has an explicit ID
    column) and returns the ones that are real technique nodes in the graph,
    in first-seen order, deduplicated. Trusting an explicit ID beats
    re-deriving it via semantic search on unrelated columns.
    """
    seen = []
    for match in TECHNIQUE_ID_RE.finditer(text or ""):
        # ATT&CK IDs are canonical uppercase in the graph, but CTI feeds
        # routinely serialize them as lowercase/mixed case. Normalize only
        # the identifier, not surrounding evidence text.
        candidate = match.group(0).upper()
        if candidate in seen:
            continue
        node = engine.query_node(candidate)
        if node and node.get('type') == 'attack_technique':
            seen.append(candidate)
    return seen


def extract_named_techniques(engine, text):
    """Return real ATT&CK techniques whose complete canonical name appears in text.

    This is deliberately an exact phrase match, not another fuzzy/LLM inference:
    it allows a CTI artifact such as "used Phishing, Valid Accounts, and Remote
    Services" to yield all three graph-backed TTPs without minting an ID. Literal
    IDs remain authoritative; this is the deterministic next-best evidence when
    an artifact names ATT&CK behaviors but omits their IDs.
    """
    # graph_engine maintains a longest/specific-first exact-name index with
    # real Unicode word boundaries and parent/sub-technique suppression.  The
    # old inline regex used ``\\w`` (a literal slash+w) and could match a name
    # inside a larger word; scanning every graph node per observation was also
    # needlessly expensive.
    return engine.match_attack_technique_names(text)


def resolve_technique(engine, finding_text):
    """Semantic-search a finding to its MITRE ATT&CK technique.

    Same filter rule as agent_batch_processor.py: take the first semantic
    search hit whose node id looks like a technique id ('T' followed by a
    digit). Returns (node_id, node_data, score) or None.
    """
    # semantic_search is typed to attack_technique by default.  Do not rank
    # every graph node and then use a first matching T-prefixed result.
    mitre_results = engine.semantic_search(
        finding_text, top_k=2, node_type='attack_technique'
    )
    if not mitre_results:
        return None
    best = mitre_results[0]
    best_score = float(best[2])
    second_score = float(mitre_results[1][2]) if len(mitre_results) > 1 else None
    # A semantic/lexical result is evidence for triage, not an authority.  If
    # it is weak or effectively tied with another technique, leave the source
    # unresolved for review instead of emitting a confident-looking report.
    if best_score < SEMANTIC_MIN_SCORE:
        return None
    if second_score is not None and best_score - second_score < SEMANTIC_MIN_MARGIN:
        return None
    return best


def resolve_techniques(engine, row, finding_text):
    """Resolves ALL ATT&CK techniques relevant to one row.

    Priority order:
    1. Literal technique IDs mentioned anywhere in the row -- authoritative.
    2. Complete canonical ATT&CK technique names mentioned in the row -- also
       deterministic, and may yield several TTPs from one CTI artifact.
    3. Otherwise, semantic-search finding_text and take the single highest-
       scoring technique match (the conservative fallback behavior).

    Returns (node_id, node_data, score, resolution_method) tuples. A source
    artifact can appear in several technique groups when it contains several
    independently evidenced TTPs.
    """
    row_text = " | ".join(
        str(value) for column, value in row.items()
        if not str(column).startswith('_') and pd.notna(value)
    )
    direct_ids = extract_direct_technique_ids(engine, row_text)
    named_ids = extract_named_techniques(engine, row_text)
    resolved = []
    for tid in direct_ids:
        resolved.append((tid, engine.query_node(tid), 1.0, "explicit_attack_id"))
    for tid in named_ids:
        if tid not in direct_ids:
            resolved.append((tid, engine.query_node(tid), 1.0, "canonical_attack_name"))
    if resolved:
        return resolved

    single = resolve_technique(engine, finding_text)
    return [(single[0], single[1], single[2], "semantic_fallback")] if single else []


def group_findings_by_technique(engine, df):
    """Groups CSV rows by resolved ATT&CK technique id(s).

    A single row can resolve to more than one technique (see
    resolve_techniques()) -- when it does, the row is attributed to every
    matching technique's group, since the underlying finding genuinely
    relates to all of them.

    Returns (groups_dict, skipped_count) where groups_dict maps
    technique_id -> {technique_name, technique_description, affected_hosts,
    severity_breakdown}.
    """
    groups = {}
    skipped_count = 0

    for index, row in df.iterrows():
        finding_text = compose_finding_text(row, ['Finding', 'Observation', 'Vulnerability', 'Description'])
        ip = first_present(row, ['IP', 'Target Address', 'Address'], default="N/A")
        hostname = first_present(row, ['Hostname', 'Host', 'Target'], default="N/A")
        severity = first_present(row, ['Severity'], default="Unknown")
        source_sheet = first_present(row, ['_sheet'], default="")
        source_row = first_present(row, ['_source_row'], default=str(index + 1))

        mitre_nodes = resolve_techniques(engine, row, finding_text)
        if not mitre_nodes:
            print(f"[{index}] No MITRE technique found for '{finding_text}' -- skipping")
            skipped_count += 1
            continue

        for t_code, mitre_node_data, score, resolution_method in mitre_nodes:
            if t_code not in groups:
                groups[t_code] = {
                    "technique_name": mitre_node_data.get('name', 'Unknown'),
                    "technique_description": mitre_node_data.get('description', 'Unknown'),
                    "affected_hosts": [],
                    "severity_breakdown": {},
                    "requires_review": False,
                }

            group = groups[t_code]
            group["affected_hosts"].append({
                "ip": ip,
                "hostname": hostname,
                "finding_text": finding_text,
                "severity": severity,
                "resolution_method": resolution_method,
                "resolution_score": score,
                "source_locator": {
                    "sheet": source_sheet,
                    "row": source_row,
                    "dataframe_index": int(index) if isinstance(index, int) else str(index),
                },
            })
            if resolution_method == "semantic_fallback":
                group["requires_review"] = True
            group["severity_breakdown"][severity] = group["severity_breakdown"].get(severity, 0) + 1

    print(f"Grouped findings into {len(groups)} unique technique(s); skipped {skipped_count} row(s) with no technique resolution.")
    return groups, skipped_count


def collect_framework_mappings(engine, t_code):
    """Collect every direct, graph-backed framework relationship for one TTP.

    The legacy markdown fields retain a primary relationship for readability,
    but this structured result is intentionally exhaustive. It is written to
    every report JSON so downstream systems can consume one-or-more ZIG,
    CREF, NIST, and CSA mappings without scraping prose or losing secondary
    relationships.
    """
    # This is intentionally a thin compatibility wrapper.  The authoritative
    # implementation lives in GraphMappingService, which preserves multi-edges,
    # returns all validated provenance paths, labels inherited parent mappings,
    # and includes both native ATT&CK and CREF mitigations.  Do not add another
    # first-hit graph crawl here.
    return engine.get_framework_bundle(t_code)


def crawl_correlation(engine, t_code):
    """Build legacy display fields from the authoritative mapping service.

    The former implementation performed a second, first-hit graph walk and
    used unvalidated keyword fallbacks when a direct crosswalk was absent.
    That was both lossy under ``MultiDiGraph`` and capable of presenting a
    guessed ZIG mapping as fact.  This adapter intentionally derives every
    scalar display field from the full validated bundle; the bundle itself is
    retained unchanged for JSON/API consumers.
    """
    bundle = collect_framework_mappings(engine, t_code)
    node = engine.query_node(t_code) or {}

    def label(item_id, name):
        return f"[{item_id}] {name or item_id}" if item_id else "None found in graph"

    def unique(values):
        return list(dict.fromkeys(value for value in values if value))

    def path_node_labels(*node_types):
        """Return every distinct validated node label of the requested type.

        The framework bundle's path records are authoritative and may contain
        defensive artifacts that do not have a lossy legacy scalar summary.
        Pulling labels from those paths keeps the Markdown report complete
        without inventing an additional graph traversal.
        """
        wanted = set(node_types)
        return unique(
            label(node.get("id"), node.get("name"))
            for path in bundle.get("paths", [])
            if path.get("validation", {}).get("state") == "valid"
            for node in path.get("nodes", [])
            if node.get("type") in wanted and node.get("id")
        )

    tactics = bundle.get("attack_tactics") or []
    zig = bundle.get("zig") or []
    cref = bundle.get("cref") or []
    mitigations = bundle.get("mitigations") or []
    csa = bundle.get("csa") or []
    d3fend = bundle.get("d3fend") or []
    analytics = bundle.get("analytics") or []

    primary_zig = zig[0] if zig else {}
    primary_cref = cref[0] if cref else {}
    primary_mitigation = mitigations[0] if mitigations else {}

    return {
        "tactic": ", ".join(
            label(item.get("tactic_id"), item.get("tactic_name")) for item in tactics
        ) or "Unknown Tactic",
        "technique_description": node.get("description", "Unknown"),
        "d3fend_countermeasures": unique(
            label(item.get("d3fend_id"), item.get("d3fend_name")) for item in d3fend
        ),
        # Render every artifact found on a validated mapping path.  The full
        # path bundle remains available for provenance, while this stable,
        # de-duplicated list makes the human Markdown report complete too.
        "d3fend_artifacts": path_node_labels("defensive_artifact", "attack_datacomponent"),
        "mitre_analytics": unique(
            label(item.get("analytic_id"), item.get("analytic_description") or item.get("analytic_name"))
            for item in analytics
        ),
        "mitre_mitigations": unique(
            label(item.get("mitigation_id"), item.get("mitigation_name")) for item in mitigations
        ),
        "zig_pillar": primary_zig.get("pillar_name", "Unknown Pillar"),
        "zig_activity_id": primary_zig.get("activity_id", "None found"),
        "zig_activity_name": primary_zig.get("activity_name", "No matching ZIG activity"),
        "zig_capability_id": primary_zig.get("capability_id", "None found"),
        "zig_capability_name": primary_zig.get("capability_name", "No matching ZIG activity"),
        "zig_technologies": path_node_labels("zig_technology"),
        "cref_goal": primary_cref.get("goal_name", "None found in graph"),
        "cref_objective": primary_cref.get("objective_name", "None found in graph"),
        "cref_technique": primary_cref.get("technique_name", "None found in graph"),
        "cref_approach": primary_cref.get("approach_name", "None found in graph"),
        "cref_approach_id": primary_cref.get("approach_id", "None"),
        "cref_effect": primary_cref.get("effect_name", "None found in graph"),
        "cref_mitigation_id": primary_mitigation.get("mitigation_id", "None found in graph"),
        "cref_mitigation_name": primary_mitigation.get("mitigation_name", "No matching CREF/ATT&CK mitigation with a control mapping"),
        "nist_controls": unique(
            control for mitigation in mitigations for control in mitigation.get("nist_800_53_controls", [])
        ),
        "traceability": (
            f"Validated mapping matrix {bundle.get('mapping_matrix_version')} / "
            f"graph snapshot {bundle.get('graph_snapshot_id')}"
        ),
        "csa_name": ", ".join(
            label(item.get("csa_id"), item.get("csa_name")) for item in csa
        ) or "None found in graph",
        "framework_mappings": bundle,
    }


def build_context(t_code, group_data, correlation_data):
    """Merge group/correlation data into a full human-report context.

    The downstream LLM receives its own bounded view via ``_llm_context``.
    Keeping all observations here ensures the immutable Markdown report and
    its JSON twin contain the complete source set instead of a 50-row preview.
    """
    affected_hosts = group_data["affected_hosts"]
    finding_count = len(affected_hosts)

    context = {
        "technique_id": t_code,
        "technique_name": group_data["technique_name"],
        "technique_description": group_data["technique_description"],
        "affected_hosts": affected_hosts,
        "finding_count": finding_count,
        "severity_breakdown": group_data["severity_breakdown"],
        "hosts_truncated_note": None,
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
