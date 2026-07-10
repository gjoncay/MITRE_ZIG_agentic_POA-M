import pandas as pd
import json
import re
import os

nodes = {} # id -> {id, type, name, description, url}
edges = set() # (source_id, target_id, relationship_type)

def add_node(id, type, name, description="", url=""):
    if pd.isna(id) or not id: return
    id = str(id).strip()
    if id not in nodes:
        nodes[id] = {
            "id": id,
            "type": type,
            "name": str(name).strip() if pd.notna(name) else "",
            "description": str(description).strip() if pd.notna(description) else "",
            "url": str(url).strip() if pd.notna(url) else ""
        }

def add_edge(source_id, target_id, rel_type):
    if pd.isna(source_id) or pd.isna(target_id) or not source_id or not target_id: return
    edges.add((str(source_id).strip(), str(target_id).strip(), str(rel_type).strip()))

print("Parsing enterprise-attack-v19.1(1).xlsx...")
attack_xls = pd.ExcelFile('enterprise-attack-v19.1(1).xlsx')

# Parse Tactics first so we can map tactic names -> TA IDs on technique edges
print(" - tactics")
df_tac = attack_xls.parse('tactics')
tactic_name_to_id = {}
for _, row in df_tac.iterrows():
    add_node(row['ID'], 'attack_tactic', row['name'], row.get('description'), row.get('url'))
    tactic_name_to_id[str(row['name']).strip().lower()] = str(row['ID']).strip()

# Parse Techniques
print(" - techniques")
df_tech = attack_xls.parse('techniques')
for _, row in df_tech.iterrows():
    add_node(row['ID'], 'attack_technique', row['name'], row.get('description'), row.get('url'))
    if pd.notna(row.get('tactics')):
        # The 'tactics' column holds tactic NAMES (e.g. "Privilege Escalation").
        # Resolve them to TA-IDs so the edge points at a real node.
        for tactic in str(row['tactics']).split(','):
            tactic_id = tactic_name_to_id.get(tactic.strip().lower())
            if tactic_id:
                add_edge(row['ID'], tactic_id, 'belongs_to_tactic')
    if pd.notna(row.get('sub-technique of')):
        add_edge(row['ID'], row['sub-technique of'], 'subtechnique_of')

# Parse Mitigations
print(" - mitigations")
df_mit = attack_xls.parse('mitigations')
for _, row in df_mit.iterrows():
    add_node(row['ID'], 'attack_mitigation', row['name'], row.get('description'), row.get('url'))

# Parse Groups / Software / Campaigns (sources of the 'uses' relationships)
for sheet, node_type in [('groups', 'attack_group'), ('software', 'attack_software'), ('campaigns', 'attack_campaign')]:
    print(f" - {sheet}")
    df_s = attack_xls.parse(sheet)
    for _, row in df_s.iterrows():
        add_node(row['ID'], node_type, row['name'], row.get('description'), row.get('url'))

# Parse Data Components
print(" - datacomponents")
df_dc = attack_xls.parse('datacomponents')
for _, row in df_dc.iterrows():
    add_node(row['ID'], 'attack_datacomponent', row['name'], row.get('description'), row.get('url'))

# Parse Detection Strategies (sources of the 'detects' relationships)
print(" - detectionstrategies")
df_ds = attack_xls.parse('detectionstrategies')
for _, row in df_ds.iterrows():
    add_node(row['ID'], 'attack_detectionstrategy', row['name'], "", row.get('url'))

# Parse Analytics (build STIX-ID -> AN-ID map for the defensive mappings sheet)
print(" - analytics")
df_an = attack_xls.parse('analytics')
analytic_stix_to_id = {}
for _, row in df_an.iterrows():
    add_node(row['ID'], 'attack_analytic', row['name'], row.get('description'), row.get('url'))
    if pd.notna(row.get('STIX ID')):
        analytic_stix_to_id[str(row['STIX ID']).strip()] = str(row['ID']).strip()

# Parse Defensive Mappings: DetectionStrategy -> Analytic -> DataComponent
print(" - defensive mappings")
df_dm = attack_xls.parse('defensive mappings')
for _, row in df_dm.iterrows():
    det_id = row.get('detection_strategy_attack_id')
    an_id = analytic_stix_to_id.get(str(row.get('analytic_id')).strip())
    dc_id = row.get('data_component_attack_id')
    if pd.notna(det_id) and an_id:
        add_edge(det_id, an_id, 'has_analytic')
    if an_id and pd.notna(dc_id):
        add_edge(an_id, dc_id, 'monitors_data_component')

# Parse ATT&CK Relationships (uses / mitigates / detects / attributed-to)
print(" - relationships")
df_rel = attack_xls.parse('relationships')
for _, row in df_rel.iterrows():
    source_id = row.get('source ID')
    target_id = row.get('target ID')
    rel_type = row.get('mapping type')
    if pd.notna(source_id) and pd.notna(target_id):
        add_edge(source_id, target_id, rel_type)

print("Parsing d3fend.csv...")
df_d3 = pd.read_csv('d3fend.csv')
d3fend_tech_name_to_id = {}
for _, row in df_d3.iterrows():
    tech_id = row.get('ID')
    tactic_name = row.get('D3FEND Tactic')
    # The technique name lives in one of three hierarchy columns depending on depth
    tech_name = row.get('D3FEND Technique')
    if pd.isna(tech_name): tech_name = row.get('D3FEND Technique Level 0')
    if pd.isna(tech_name): tech_name = row.get('D3FEND Technique Level 1')
    desc = row.get('Definition')
    if pd.notna(tech_id):
        tech_id_str = str(tech_id).strip()
        add_node(tech_id_str, 'd3fend_technique', tech_name, desc)

        if pd.notna(tech_name):
            d3fend_tech_name_to_id[str(tech_name).strip().lower()] = tech_id_str

        if pd.notna(tactic_name):
            tactic_id = "D3-TAC-" + str(tactic_name).replace(" ", "-").upper()
            add_node(tactic_id, 'd3fend_tactic', tactic_name)
            add_edge(tech_id_str, tactic_id, 'belongs_to_tactic')

print("Parsing ATT&CK_D3FEND_Mappings.ods...")
try:
    mappings_xls = pd.ExcelFile('ATT&CK_D3FEND_Mappings.ods', engine='odf')
    df_map = mappings_xls.parse('Sheet1')
    for _, row in df_map.iterrows():
        attack_id = row.get('ATT&CK ID')
        d3fend_techs = row.get('Related D3FEND Techniques')
        if pd.notna(attack_id) and pd.notna(d3fend_techs):
            # Cells contain concatenated "D3-CODE Name" entries with no separator,
            # so extract the D3 codes directly (they match d3fend.csv IDs).
            for dt_id in re.findall(r'D3-[A-Z0-9]+', str(d3fend_techs)):
                add_edge(attack_id, dt_id, 'mapped_to_d3fend_technique')
except Exception as e:
    print("Warning: Could not parse ATT&CK_D3FEND_Mappings.ods:", e)

print("Parsing d3fend-full-mappings.csv...")
df_full_map = pd.read_csv('d3fend-full-mappings.csv')
for _, row in df_full_map.iterrows():
    def_tech = row.get('def_tech_label')
    def_tactic = row.get('def_tactic_label')
    def_artifact = row.get('def_artifact_label')
    off_artifact = row.get('off_artifact_label')
    off_tech_id = row.get('off_tech_id')

    # Relationships
    def_artifact_rel = row.get('def_artifact_rel_label')
    off_artifact_rel = row.get('off_artifact_rel_label')

    if pd.notna(def_tech):
        dt_lower = str(def_tech).strip().lower()
        dt_id = d3fend_tech_name_to_id.get(dt_lower, "D3-" + str(def_tech).replace(" ", "-").upper())
        add_node(dt_id, 'd3fend_technique', def_tech)

        if pd.notna(def_tactic):
            tac_id = "D3-TAC-" + str(def_tactic).replace(" ", "-").upper()
            add_node(tac_id, 'd3fend_tactic', def_tactic)
            add_edge(dt_id, tac_id, 'belongs_to_tactic')

        if pd.notna(def_artifact):
            da_id = "DA-" + str(def_artifact).replace(" ", "-").upper()
            add_node(da_id, 'defensive_artifact', def_artifact)
            add_edge(dt_id, da_id, def_artifact_rel if pd.notna(def_artifact_rel) else 'relates_to')

            if pd.notna(off_artifact):
                oa_id = "OA-" + str(off_artifact).replace(" ", "-").upper()
                add_node(oa_id, 'offensive_artifact', off_artifact)
                add_edge(da_id, oa_id, 'targets')

                if pd.notna(off_tech_id):
                    add_edge(oa_id, off_tech_id, off_artifact_rel if pd.notna(off_artifact_rel) else 'used_by')

# Integrity pass: drop any edge whose endpoint is not a real node. Without this,
# NetworkX silently creates attribute-less phantom nodes for every unknown ID.
before = len(edges)
edges = {e for e in edges if e[0] in nodes and e[1] in nodes}
dropped = before - len(edges)
if dropped:
    print(f"Integrity pass: dropped {dropped} edges referencing unknown node IDs ({len(edges)} remain).")

print("Exporting to mitre_nodes.csv and mitre_edges.csv...")
df_nodes = pd.DataFrame(list(nodes.values()))
df_nodes.to_csv('mitre_nodes.csv', index=False)

df_edges = pd.DataFrame(list(edges), columns=['source_id', 'target_id', 'relationship_type'])
df_edges.to_csv('mitre_edges.csv', index=False)

print("Exporting to ontology.json...")
ontology = {
    "nodes": list(nodes.values()),
    "edges": [{"source_id": e[0], "target_id": e[1], "relationship_type": e[2]} for e in edges]
}
with open('ontology.json', 'w') as f:
    json.dump(ontology, f, indent=2)

print(f"Done! Exported {len(nodes)} nodes and {len(edges)} edges.")
