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
