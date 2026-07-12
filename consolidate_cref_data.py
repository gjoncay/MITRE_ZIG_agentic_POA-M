"""Regenerates cref_nodes.csv / cref_edges.csv from the raw CREF/*.csv files, and
reconciles the DoD Zero Trust Strategy Pillar/Capability/Activity taxonomy found in
CREF/zero-trust-attack.csv against the EXISTING zig_nodes.csv/zig_edges.csv.

Why a separate reconciliation step: CREF/zero-trust-attack.csv encodes the same 7 DoD
Zero Trust pillars (User, Device, Network & Environment, Application & Workload, Data,
Automation & Orchestration, Visibility & Analytics) that scripts/parse_zig_data.py
already extracted from the NSA ZIG PDFs as ZIG-PIL-*/ZIG-CAP-*/ZIG-ACT-* nodes. Treating
it as a fresh taxonomy would duplicate every pillar/capability/activity. Instead this
script:
  - reuses the existing ZIG-PIL-{n} / ZIG-CAP-{id} / ZIG-ACT-{id} node IDs verbatim
  - ADDS the ~3 capabilities and ~59 activities present in the new dataset but missing
    from the PDF extraction
  - OVERWRITES existing zig_activity name/description with the new dataset's clean text
    (the PDF extraction is dot-leader/pagination garbage, e.g. "Inventory User ... D-";
    zero-trust-attack.csv's activity_name/activity_description is the authoritative
    source of truth for this layer)
  - never touches zig_pillar or existing zig_capability names (those extracted fine)

New node types this script introduces (none of these previously existed in the graph):
  cref_goal, cref_objective, cref_technique, cref_approach,
  cref_design_principle_strategic, cref_design_principle_structural,
  csa (DoD Cyber Survivability Attribute), cref_effect,
  cref_mitigation (CM#### catalog), nist_800_53_control

Source files (NIST SP 800-160 Vol 2 Cyber Resiliency Engineering Framework, the DoD
Cyber Survivability Endorsement Implementation Guide, and the DoD Zero Trust Strategy
activity-level crosswalk):
  CREF/cref-relationships.csv          Goal -> Objective -> Technique -> Approach (canonical taxonomy)
  CREF/design-principles-cref.csv      Strategic/Structural Design Principle -> Technique
  CREF/csa-cref-attack.csv             CSA -> Design Principles -> Technique/Approach -> ATT&CK
  CREF/impact.csv                      Technique/Approach -> Effect
  CREF/attack-relationships-sankey-export.csv   Approach -> ATT&CK -> CM Mitigation -> NIST 800-53 Control
  CREF/zero-trust-attack.csv           ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation

Run after ANY change to the CREF/ raw files:
    python3 consolidate_cref_data.py
"""
import csv
import os
import re

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREF_DIR = os.path.join(BASE_DIR, "CREF")

# ---------------------------------------------------------------------------
# New CREF/CSA/NIST-control nodes + edges (written to cref_nodes.csv / cref_edges.csv)
# ---------------------------------------------------------------------------
cref_nodes = {}   # id -> {id, type, name, description, url}
cref_edges = set()  # (source_id, target_id, relationship_type)


def cref_id(prefix, raw):
    """Turns a raw CREF id ('g1', 'sta4', 'a45') into a globally unique node id."""
    digits = re.sub(r"[^0-9.]", "", str(raw))
    return f"{prefix}-{digits}"


def add_cref_node(id_, type_, name, description=""):
    if pd.isna(id_) or not str(id_).strip():
        return None
    id_ = str(id_).strip()
    if id_ not in cref_nodes:
        cref_nodes[id_] = {
            "id": id_,
            "type": type_,
            "name": str(name).strip() if pd.notna(name) else "",
            "description": str(description).strip() if pd.notna(description) else "",
            "url": "",
        }
    elif not cref_nodes[id_]["description"] and pd.notna(description) and str(description).strip():
        cref_nodes[id_]["description"] = str(description).strip()
    return id_


def add_cref_edge(source_id, target_id, rel_type):
    if pd.isna(source_id) or pd.isna(target_id):
        return
    source_id, target_id = str(source_id).strip(), str(target_id).strip()
    if not source_id or not target_id:
        return
    cref_edges.add((source_id, target_id, rel_type))


def read_csv(name):
    return pd.read_csv(os.path.join(CREF_DIR, name))


# Some rows use a native ATT&CK Mitigation ID (e.g. "M1026") in the mitigation_id
# column instead of the DoD CM#### catalog. Those nodes already exist in
# mitre_nodes.csv as type attack_mitigation -- writing them into cref_nodes.csv as
# type cref_mitigation would silently overwrite the correct type when the graph
# loads mitre_nodes.csv then cref_nodes.csv. Detect and skip node creation for them
# (edges to/from them still get added normally).
print("Loading mitre_nodes.csv IDs (native-mitigation collision check)...")
with open(os.path.join(BASE_DIR, "mitre_nodes.csv"), encoding="utf-8") as f:
    mitre_ids = {row["id"] for row in csv.DictReader(f)}


def add_mitigation_node(raw_id, name):
    mid = str(raw_id).strip() if pd.notna(raw_id) else ""
    if not mid:
        return None
    if mid in mitre_ids:
        return mid
    return add_cref_node(mid, "cref_mitigation", name)


print("Parsing cref-relationships.csv (canonical Goal->Objective->Technique->Approach)...")
df = read_csv("cref-relationships.csv")
for _, row in df.iterrows():
    g = add_cref_node(cref_id("CREF-GOAL", row["goal_id"]), "cref_goal", row["Goal"], row.get("goal_description"))
    o = add_cref_node(cref_id("CREF-OBJ", row["obj_id"]), "cref_objective", row["Objective"], row.get("obj_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["Technique"], row.get("tech_description"))
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["Approach"], row.get("app_description"))
    if g and o:
        add_cref_edge(o, g, "serves_goal")
    if o and t:
        add_cref_edge(t, o, "achieves_objective")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")

print("Parsing design-principles-cref.csv...")
df = read_csv("design-principles-cref.csv")
for _, row in df.iterrows():
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    rel = "requires_principle" if pd.notna(row.get("required")) and int(row["required"]) == 1 else "informs_principle"
    if t and sta:
        add_cref_edge(t, sta, rel)
    if t and stu:
        add_cref_edge(t, stu, rel)

print("Parsing csa-cref-attack.csv (DoD Cyber Survivability Attributes)...")
df = read_csv("csa-cref-attack.csv")
for _, row in df.iterrows():
    csa = add_cref_node(str(row["csa_id"]).strip(), "csa", row["csa_name"])
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["APPROACH_ID"]), "cref_approach", row["approach"])
    if csa and sta:
        add_cref_edge(csa, sta, "embodies_principle")
    if csa and stu:
        add_cref_edge(csa, stu, "embodies_principle")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if csa and t:
        add_cref_edge(csa, t, "associated_with_technique")
    if a and pd.notna(row.get("attack_technique_id")):
        add_cref_edge(a, str(row["attack_technique_id"]).strip(), "mitigates_architecturally")

print("Parsing impact.csv (Approach -> Effect)...")
df = read_csv("impact.csv")
for _, row in df.iterrows():
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["approach_id"]), "cref_approach", row["approach"])
    e = add_cref_node(cref_id("CREF-EFFECT", row["effect_id"]), "cref_effect", row["effect"])
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if a and e:
        add_cref_edge(a, e, "has_effect")

print("Parsing attack-relationships-sankey-export.csv (Approach -> ATT&CK -> CM Mitigation -> NIST 800-53)...")
df = read_csv("attack-relationships-sankey-export.csv")
for _, row in df.iterrows():
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["approach"], row.get("app_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["technique"], row.get("tech_description"))
    if a and t:
        add_cref_edge(a, t, "realizes_technique")

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and pd.notna(row.get("control")):
            control = add_cref_node(str(row["control"]).strip(), "nist_800_53_control", row["control"])
            if cm and control:
                add_cref_edge(cm, control, "satisfies_control")

# ---------------------------------------------------------------------------
# zero-trust-attack.csv: reconcile against existing ZIG nodes, then add the new
# cref_mitigation/cref_approach edges plus the direct ZIG-activity<->ATT&CK bridge.
# ---------------------------------------------------------------------------
print("Loading existing zig_nodes.csv / zig_edges.csv for reconciliation...")
zig_nodes = {}
with open(os.path.join(BASE_DIR, "zig_nodes.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_nodes[row["id"]] = dict(row)

zig_edges = set()
with open(os.path.join(BASE_DIR, "zig_edges.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_edges.add((row["source_id"], row["target_id"], row["relationship_type"]))

new_zig_activities = new_zig_capabilities = 0

print("Parsing zero-trust-attack.csv (ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation)...")
df = read_csv("zero-trust-attack.csv")
for _, row in df.iterrows():
    pillar_id = str(row["pillar_id"]).strip() if pd.notna(row.get("pillar_id")) else None
    cap_id = str(row["capability_id"]).strip() if pd.notna(row.get("capability_id")) else None
    act_id = str(row["activity_id"]).strip() if pd.notna(row.get("activity_id")) else None

    zig_pil = f"ZIG-PIL-{pillar_id}" if pillar_id else None
    zig_cap = f"ZIG-CAP-{cap_id}" if cap_id else None
    zig_act = f"ZIG-ACT-{act_id}" if act_id else None

    # Add capabilities missing from the PDF extraction (never overwrite existing ones).
    if zig_cap and zig_cap not in zig_nodes:
        zig_nodes[zig_cap] = {"id": zig_cap, "type": "zig_capability",
                               "name": str(row["capability_name"]).strip(), "description": "", "url": ""}
        new_zig_capabilities += 1
        if zig_pil:
            zig_edges.add((zig_cap, zig_pil, "belongs_to_pillar"))

    # Activities: add if missing, or overwrite the PDF-scraped garbage name/description
    # with this dataset's clean text (authoritative source for this layer).
    if zig_act:
        clean_name = str(row["activity_name"]).strip() if pd.notna(row.get("activity_name")) else ""
        clean_desc = str(row["activity_description"]).strip() if pd.notna(row.get("activity_description")) else ""
        if zig_act not in zig_nodes:
            zig_nodes[zig_act] = {"id": zig_act, "type": "zig_activity",
                                   "name": clean_name, "description": clean_desc, "url": ""}
            new_zig_activities += 1
            if zig_cap:
                zig_edges.add((zig_act, zig_cap, "belongs_to_capability"))
        elif clean_name:
            zig_nodes[zig_act]["name"] = clean_name
            zig_nodes[zig_act]["description"] = clean_desc

    a = add_cref_node(cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("approach")) \
        if pd.notna(row.get("app_id")) else None

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    # The direct ZIG-activity <-> ATT&CK bridge: previously this correlation only
    # existed via fuzzy keyword matching of D3FEND countermeasure names (see
    # threat_assessment_skill.md Step 4). This is a precise graph edge instead.
    if zig_act and attack_id:
        cref_edges.add((zig_act, attack_id, "mitigates"))

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and zig_act:
            add_cref_edge(cm, zig_act, "implements_activity")

print(f"  Added {new_zig_capabilities} new zig_capability nodes, {new_zig_activities} new zig_activity nodes.")
print(f"  Cleaned activity names/descriptions for {len(df['activity_id'].dropna().astype(str).str.strip().unique()) - new_zig_activities} existing zig_activity nodes.")

# ---------------------------------------------------------------------------
# Integrity pass: drop cref_edges whose endpoint is not a real node anywhere in
# the graph (mitre_nodes.csv, the now-reconciled zig_nodes, or our own new nodes).
# Mirrors the same pass in consolidate_mitre_data.py.
# ---------------------------------------------------------------------------
known_ids = set(cref_nodes.keys()) | set(zig_nodes.keys()) | mitre_ids
before = len(cref_edges)
cref_edges = {e for e in cref_edges if e[0] in known_ids and e[1] in known_ids}
dropped = before - len(cref_edges)
if dropped:
    print(f"Integrity pass: dropped {dropped} edges referencing unknown node IDs ({len(cref_edges)} remain).")

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
print("Writing cref_nodes.csv / cref_edges.csv...")
pd.DataFrame(list(cref_nodes.values())).to_csv(os.path.join(BASE_DIR, "cref_nodes.csv"), index=False)
pd.DataFrame(list(cref_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "cref_edges.csv"), index=False)

print("Writing reconciled zig_nodes.csv / zig_edges.csv...")
pd.DataFrame(list(zig_nodes.values())).to_csv(os.path.join(BASE_DIR, "zig_nodes.csv"), index=False)
pd.DataFrame(list(zig_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "zig_edges.csv"), index=False)

print(f"Done! CREF: {len(cref_nodes)} nodes, {len(cref_edges)} edges. "
      f"ZIG (reconciled): {len(zig_nodes)} nodes, {len(zig_edges)} edges.")
