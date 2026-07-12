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
TECHNIQUE_ID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')


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
        if pd.notna(val) and str(val).strip() and str(val).strip().lower() != 'nan'
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
        candidate = match.group(0)
        if candidate in seen:
            continue
        node = engine.query_node(candidate)
        if node and node.get('type') == 'attack_technique':
            seen.append(candidate)
    return seen


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


def resolve_techniques(engine, row, finding_text):
    """Resolves ALL ATT&CK techniques relevant to one row.

    Priority order:
    1. Any literal technique ID mentioned anywhere in the row (any column, or
       the composed finding_text) -- trust an explicit label over a guess.
       A single row CAN yield more than one technique this way (e.g. a CTI
       excerpt or a Navigator export row that cites two IDs).
    2. Otherwise, semantic-search finding_text and take the single
       highest-scoring technique match (the original, unchanged behavior).

    Returns a list of (node_id, node_data, score) tuples -- usually length 1,
    occasionally more, possibly empty.
    """
    row_text = " | ".join(str(v) for v in row.values if pd.notna(v))
    direct_ids = extract_direct_technique_ids(engine, row_text)
    if direct_ids:
        return [(tid, engine.query_node(tid), 1.0) for tid in direct_ids]

    single = resolve_technique(engine, finding_text)
    return [single] if single else []


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

        mitre_nodes = resolve_techniques(engine, row, finding_text)
        if not mitre_nodes:
            print(f"[{index}] No MITRE technique found for '{finding_text}' -- skipping")
            skipped_count += 1
            continue

        for t_code, mitre_node_data, score in mitre_nodes:
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
