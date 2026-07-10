import sys
import os
import pandas as pd
from datetime import datetime

# Add the scripts directory to path to import graph_engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
from graph_engine import KnowledgeGraphEngine

def generate_reports():
    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()
    
    # Read the flattened mock data
    try:
        df = pd.read_csv("processed_assessment.csv")
    except FileNotFoundError:
        print("Could not find processed_assessment.csv. Did you run ingest_assessment.py?")
        return
        
    # Let's filter for High/Critical severity issues to focus our narrow reports
    target_findings = df[df['Severity'].isin(['High', 'Critical'])].head(3)
    
    # Read the markdown template
    with open("assessment_template.md", "r") as f:
        template = f.read()

    output_dir = "mock_output"
    os.makedirs(output_dir, exist_ok=True)
    
    for index, row in target_findings.iterrows():
        finding_text = row['Finding']
        ip = row['IP']
        hostname = row['Hostname']
        
        print(f"\n[{index}] Processing Threat: {finding_text}")
        
        # 1. Graph Mapping (Semantic Search)
        # Fetch a wider net to find the top Technique (T-code)
        mitre_results = engine.semantic_search(finding_text, top_k=20)
        mitre_node = None
        for res in mitre_results:
            nid = res[0]
            if nid.startswith('T') and nid[1].isdigit():
                mitre_node = res
                break
                
        if not mitre_node:
            print(f"[{index}] No MITRE technique found for '{finding_text}'")
            continue
            
        mitre_node_id, mitre_node_data, score = mitre_node
        mitre_name = mitre_node_data.get('name', 'Unknown')
        
        # 1.5 Extract Tactic
        mitre_tactic = "Unknown Tactic"
        for u, v, data in engine.graph.out_edges(mitre_node_id, data=True):
            if data.get('relationship') == 'belongs_to_tactic':
                mitre_tactic = v
                break
        
        # 2. Mitigation Crawl (D3FEND & Supplementals)
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        d3fend_countermeasures = []
        d3fend_artifacts = []
        analytics = []
        mitigations = []
        
        if mitre_subgraph:
            for nid, ndata in mitre_subgraph['nodes'].items():
                if ndata.get('type') == 'd3fend_countermeasure':
                    d3fend_countermeasures.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ndata.get('type') == 'd3fend_artifact':
                    d3fend_artifacts.append(f"[{nid}] {ndata.get('name', nid)}")
                elif nid.startswith('AN'):
                    analytics.append(f"[{nid}] {ndata.get('name', 'Analytic')}")
                elif nid.startswith('M') and nid[1].isdigit():
                    mitigations.append(f"[{nid}] {ndata.get('name', 'Mitigation')}")
                    
        d3fend_cm_str = "\n  - ".join(d3fend_countermeasures[:3]) if d3fend_countermeasures else "System Hardening"
        if d3fend_countermeasures: d3fend_cm_str = "\n  - " + d3fend_cm_str
        d3fend_art_str = ", ".join(d3fend_artifacts[:3]) if d3fend_artifacts else "System Configuration"
        mitre_analytics_str = "\n  - ".join(analytics[:2]) if analytics else "None specified"
        mitre_mitigations_str = "\n  - ".join(mitigations[:2]) if mitigations else "None specified"
        if analytics: mitre_analytics_str = "\n  - " + mitre_analytics_str
        if mitigations: mitre_mitigations_str = "\n  - " + mitre_mitigations_str
        
        # 3. Zero Trust (ZIG) Correlation
        # We will search ZIG for the first D3FEND countermeasure, or fallback to 'Authentication' / 'Access'
        search_term = d3fend_countermeasures[0] if d3fend_countermeasures else "Access"
        
        zig_results = engine.search_nodes(search_term, exact_match=False)
        zig_caps = [n for n in zig_results if n[1].get('type') == 'zig_capability']
        zig_techs = [n for n in zig_results if n[1].get('type') == 'zig_technology']
        
        zig_cap_id = zig_caps[0][0] if zig_caps else "ZIG-CAP-1.5"
        zig_cap_name = zig_caps[0][1].get('name', 'Identity Federation') if zig_caps else "Identity Federation and User Credentialing"
        zig_pillar = "User Pillar" # Simplified for this demo script
        
        zig_tech_str = ", ".join([f"[{t[0]}] {t[1].get('name')}" for t in zig_techs[:2]]) if zig_techs else "[ZIG-TECH-54] Identity Governance"
        
        # AI generated "So What" logic (mocked up based on finding)
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
            D3FEND_COUNTERMEASURE_1=d3fend_countermeasures[0] if len(d3fend_countermeasures) > 0 else "[D3-SH] System Hardening",
            D3FEND_COUNTERMEASURE_2=d3fend_countermeasures[1] if len(d3fend_countermeasures) > 1 else "[D3-CM] Continuous Monitoring",
            D3FEND_ARTIFACTS=d3fend_art_str,
            ZIG_PILLAR_NAME=zig_pillar,
            ZIG_CAPABILITY_ID=zig_cap_id,
            ZIG_CAPABILITY_NAME=zig_cap_name,
            ZIG_ACTIVITY_1="Identify and remediate vulnerable configurations",
            ZIG_TECHNOLOGY_1=zig_techs[0][1].get('name') if len(zig_techs) > 0 else "Identity Governance",
            ZIG_TECHNOLOGY_2=zig_techs[1][1].get('name') if len(zig_techs) > 1 else "Configuration Management Database (CMDB)",
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
    generate_reports()
