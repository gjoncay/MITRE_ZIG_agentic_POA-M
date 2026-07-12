import sys
import os

# Add the scripts directory to path to import graph_engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
from graph_engine import KnowledgeGraphEngine

def format_subgraph(subgraph_data):
    """Utility to print a subgraph nicely."""
    out = f"--- Crawled Depth {subgraph_data['depth_crawled']} from {subgraph_data['start_node']} ---\n"
    out += "Nodes Found:\n"
    for nid, ndata in subgraph_data['nodes'].items():
        out += f"  - [{nid}] {ndata.get('name', '')} ({ndata.get('type', '')})\n"
    out += "Edges:\n"
    for edge in subgraph_data['edges']:
        out += f"  - {edge['source']} --({edge['relationship']})--> {edge['target']}\n"
    return out

if __name__ == "__main__":
    engine = KnowledgeGraphEngine()
    
    print("\n" + "="*50)
    print("MOCK AGENT CRAWL: THREAT INTELLIGENCE ANALYSIS")
    print("="*50)
    
    threat_intel = "Red team executed a Golden Ticket attack (T1558.001) to persist on the domain."
    print(f"\n[Agent Input] {threat_intel}")
    
    print("\n[Agent] Searching MITRE framework using natural language: 'Red team executed a Golden Ticket attack'...")
    mitre_results = engine.semantic_search("Red team executed a Golden Ticket attack", top_k=1)
    if mitre_results:
        # semantic_search always returns (node_id, node_data, score) 3-tuples,
        # in both semantic and keyword-fallback modes
        mitre_node_id, mitre_node_data, score = mitre_results[0]
        print(f"[Agent] Found closest MITRE Node: {mitre_node_data['name']} (Score: {score:.2f})")
        
        print(f"\n[Agent] Crawling MITRE countermeasures for {mitre_node_id} (Depth=2)...")
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        print(format_subgraph(mitre_subgraph))
    
    print("\n[Agent] Based on the MITRE countermeasures (e.g. Identity Management), searching ZIG framework for related Zero Trust concepts...")
    # The agent determines "Identity" and "Access" are key. It searches ZIG nodes for "Authentication" or "Identity"
    zig_results = engine.search_nodes("Identity", exact_match=False)
    zig_candidates = [n for n in zig_results if n[1].get('type') == 'zig_capability']
    
    if zig_candidates:
        # Just pick the first matching capability for the example
        zig_node_id, zig_node_data = zig_candidates[0]
        print(f"[Agent] Found relevant ZIG Node: {zig_node_data['name']} ({zig_node_id})")
        
        print(f"\n[Agent] Crawling ZIG architecture for {zig_node_id} (Depth=2)...")
        zig_subgraph = engine.crawl_subgraph(zig_node_id, depth=2)
        print(format_subgraph(zig_subgraph))
        
    print("\n[Agent] Checking the same MITRE subgraph for direct CREF/ZIG-activity/NIST edges...")
    # These are the new edges added by consolidate_cref_data.py: a zig_activity or
    # cref_approach can point straight at the ATT&CK technique with 'mitigates' /
    # 'mitigates_architecturally', no keyword matching required.
    if mitre_results:
        for edge in mitre_subgraph.get('edges', []):
            if edge['target'] != mitre_node_id:
                continue
            src_data = mitre_subgraph['nodes'].get(edge['source'], {})
            src_type = src_data.get('type')
            if src_type == 'zig_activity':
                print(f"  - Direct ZIG Activity: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
            elif src_type == 'cref_approach':
                print(f"  - CREF Approach: [{edge['source']}] {src_data.get('name')} --mitigates_architecturally--> {mitre_node_id}")
            elif src_type == 'cref_mitigation':
                print(f"  - CREF/NIST Mitigation: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
                for _, v, data in engine.graph.out_edges(edge['source'], data=True):
                    if data.get('relationship') == 'satisfies_control':
                        control_node = engine.query_node(v)
                        print(f"      satisfies_control --> [{v}] (NIST SP 800-53)")

    print("\n" + "="*50)
    print("FINAL ASSESSMENT OUTPUT (MARKDOWN TEMPLATE FORMAT)")
    print("="*50 + "\n")
    
    assessment_md = f"""# Threat & Mitigation Assessment Report

**Date:** 2026-07-09
**Assessment ID:** ASMT-90210

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations.*

**Finding / Threat Input:** {threat_intel}

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** An adversary could use a stolen or forged Ticket Granting Ticket (TGT) to impersonate any user on the domain indefinitely, bypassing normal authentication mechanisms and password resets.
- **Potential Impact:** Complete domain compromise, allowing unhindered lateral movement, data exfiltration, and ransomware deployment.

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique.*
- **Tactic:** Credential Access (Inferred)
- **Technique(s):** [T1550.003] Use Alternate Authentication Material: Pass the Ticket
- **Description:** Adversaries may forge Kerberos tickets to bypass authentication.

### Supplemental MITRE Data (Analytics & Mitigations)
*Associated defensive guidance from the MITRE framework.*
- **Analytics/Detections:** 
  - [AN0316] Detects AS-REP roasting attempts by monitoring for Kerberos AS-REQ/AS-REP
- **Native Mitigations:** 
  - [M1038] Execution Prevention

### D3FEND Countermeasures
- **Countermeasure(s):** 
  - Credential Rotation
  - Access Control
- **Target Artifact(s):** Active Directory Ticket Granting Ticket (TGT)

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment

### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** ZIG-PIL-1 - User Pillar
- **Associated Capability:** {zig_node_id} - {zig_node_data['name']}
- **Relevant Activities:** 
  - ZIG-ACT-1.5.1 - Organizational Identity Lifecycle Management (ILM)

---

## 4. Long-Term Architectural Resiliency (CREF)

### Resiliency Chain
- **Goal:** Withstand
- **Objective:** Limit Damage
- **Technique:** Privilege Restriction
- **Approach:** Attribute-Based Usage Restriction
- **Effect:** Limit

### Architectural Recommendation
Because forged tickets bypass password-based tactical controls entirely, engineer for
attribute-based usage restriction (limit the mission's blast radius) rather than relying
solely on credential rotation.

---

## 5. NIST SP 800-53 Compliance Mapping

- **Mitigation:** CM1164 - Calibrate Administrative Access
- **Satisfies Control(s):** AC-6(1), AC-6(5)
- **Traceability:** Implements CREF Approach a33 / ZIG Activity 1.2.1

---

## 6. Technology Recommendations

- **Recommended Technologies:**
  - ZIG-TECH-54 - Identity Governance and Administration (IGA)
  - ZIG-TECH-101 - Single Sign-On (SSO) and Federation
- **Implementation Notes:** Ensure IdP is configured to enforce MFA and rotate credentials automatically on a fixed cadence.

---

## 7. Plan of Action and Milestones (POA&M)

- [ ] **Phase 1 (Immediate):** Identify and rotate all potentially compromised service account passwords (krbtgt).
- [ ] **Phase 2 (Short-Term):** Deploy robust Identity Governance and Administration (IGA) tools for continuous monitoring.
- [ ] **Phase 3 (Long-Term/Strategic):** Fully integrate Identity Federation across all enclaves per ZIG Capability 1.5.
"""
    print(assessment_md)
