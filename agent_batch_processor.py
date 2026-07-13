"""LEGACY demonstration batch reporter.

This script is retained for backwards-compatible examples only.  Production
analysis, review state, and report lifecycle now belong to
``run_analyst_pipeline.py`` and the web API.  Its graph reads use the typed
repository facade so parallel relationship rows in the MultiDiGraph are not
collapsed or accessed through single-edge assumptions.
"""

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
    print("LEGACY EXAMPLE: use run_analyst_pipeline.py for supported report generation.")
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
        for edge in engine.repository.outgoing(
            mitre_node_id, 'belongs_to_tactic', target_type='attack_tactic'
        ):
            tactic_id = edge['target_id']
            tactic_node = engine.query_node(tactic_id)
            mitre_tactic = f"[{tactic_id}] {tactic_node.get('name', tactic_id)}" if tactic_node else tactic_id
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
                if edge.get('target_id') != mitre_node_id:
                    continue
                source_id = edge['source_id']
                src_data = mitre_subgraph['nodes'].get(source_id, {})
                src_type = src_data.get('type')
                if src_type == 'zig_activity' and edge.get('relationship_type') == 'mitigates':
                    zig_activities_direct.append((source_id, src_data))
                elif src_type == 'cref_approach' and edge.get('relationship_type') == 'mitigates_architecturally':
                    cref_approaches.append((source_id, src_data))
                elif src_type == 'cref_mitigation' and edge.get('relationship_type') == 'mitigates':
                    cref_mitigations.append((source_id, src_data))

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
            for edge in engine.repository.outgoing(
                zig_activity_id, 'belongs_to_capability', target_type='zig_capability'
            ):
                capability_id = edge['target_id']
                cap_node = engine.query_node(capability_id)
                zig_cap_id, zig_cap_name = capability_id, (cap_node.get('name', capability_id) if cap_node else capability_id)
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
            for edge in engine.repository.outgoing(
                zig_cap_id, 'belongs_to_pillar', target_type='zig_pillar'
            ):
                pillar_id = edge['target_id']
                pillar_node = engine.query_node(pillar_id)
                zig_pillar = pillar_node.get('name', pillar_id) if pillar_node else pillar_id
                break

        # 4. CREF Architectural Resiliency: walk the first approach up
        # Approach -> Technique -> Objective -> Goal, plus its Effect.
        cref_goal = cref_objective = cref_technique_name = cref_approach_name = cref_effect = "None found in graph"
        cref_approach_id = "None"
        cref_technique_id_found = None
        if cref_approaches:
            cref_approach_id, cref_approach_data = cref_approaches[0]
            cref_approach_name = cref_approach_data.get('name', cref_approach_id)
            for edge in engine.repository.outgoing(cref_approach_id):
                rel = edge['relationship_type']
                target_id = edge['target_id']
                if rel == 'realizes_technique':
                    cref_technique_id_found = target_id
                    tech_node = engine.query_node(target_id)
                    cref_technique_name = tech_node.get('name', target_id) if tech_node else target_id
                elif rel == 'has_effect':
                    eff_node = engine.query_node(target_id)
                    cref_effect = eff_node.get('name', target_id) if eff_node else target_id
            if cref_technique_id_found:
                for edge in engine.repository.outgoing(cref_technique_id_found):
                    rel = edge['relationship_type']
                    target_id = edge['target_id']
                    if rel == 'achieves_objective':
                        obj_node = engine.query_node(target_id)
                        cref_objective = obj_node.get('name', target_id) if obj_node else target_id
                        for goal_edge in engine.repository.outgoing(target_id, 'serves_goal'):
                            goal_id = goal_edge['target_id']
                            goal_node = engine.query_node(goal_id)
                            cref_goal = goal_node.get('name', goal_id) if goal_node else goal_id
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
            for edge in engine.repository.outgoing(cref_mitigation_id):
                rel = edge['relationship_type']
                target_id = edge['target_id']
                if rel == 'satisfies_control':
                    nist_controls.append(target_id)
                elif rel == 'implements_activity':
                    zig_activity_id_from_mitigation = target_id
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
            for edge in engine.repository.incoming(cref_technique_id_found, 'associated_with_technique'):
                source_id = edge['source_id']
                if edge['relationship_type'] == 'associated_with_technique':
                    csa_node = engine.query_node(source_id)
                    if csa_node:
                        csa_name = csa_node.get('name', source_id)
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
