import re
import csv
import os

PILLARS = {
    1: "User",
    2: "Device",
    3: "Application and Workload",
    4: "Data",
    5: "Network and Environment",
    6: "Automation and Orchestration",
    7: "Visibility and Analytics"
}

def parse_zig_text_files(files):
    capabilities = {}
    activities = {}

    cap_pattern = re.compile(r'^Capability\s+(\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$')
    act_pattern = re.compile(r'^Activity\s+(\d+\.\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$')

    for fpath in files:
        if not os.path.exists(fpath):
            continue
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Check for Capability
                c_match = cap_pattern.search(line)
                if c_match:
                    c_id = c_match.group(1)
                    c_name = c_match.group(2).strip()
                    # Strip trailing dots and page numbers if any
                    c_name = re.sub(r'\s*\.{2,}\s*\d*$', '', c_name).strip()
                    if c_id not in capabilities or len(c_name) > len(capabilities[c_id]): 
                        capabilities[c_id] = c_name
                
                # Check for Activity
                a_match = act_pattern.search(line)
                if a_match:
                    a_id = a_match.group(1)
                    a_name = a_match.group(2).strip()
                    a_name = re.sub(r'\s*\.{2,}\s*\d*$', '', a_name).strip()
                    if a_id not in activities or len(a_name) > len(activities[a_id]):
                        activities[a_id] = a_name

    return capabilities, activities

def parse_tech_mappings(fpath):
    mappings = []
    technologies = {}
    tech_id_counter = 1
    
    with open(fpath, 'r', encoding='utf-8') as f:
        lines = f.read().strip().split('\n')
        
    i = 0
    while i < len(lines):
        tech_name = lines[i].strip()
        if not tech_name:
            i += 1
            continue
        if i + 1 >= len(lines):
            break
            
        caps_line = lines[i+1].strip()
        count_line = lines[i+2].strip() if i + 2 < len(lines) else ""
        
        # Extract capabilities like 4.4P45.1P5 -> 4.4, 5.1
        caps = re.findall(r'(\d+\.\d+)P\d', caps_line)
        
        tech_id = f"ZIG-TECH-{tech_id_counter}"
        technologies[tech_id] = tech_name
        tech_id_counter += 1
        
        for cap in caps:
            mappings.append((tech_id, cap))
            
        i += 3
        
    return technologies, mappings

def generate_csvs(capabilities, activities, technologies, tech_mappings):
    nodes = []
    edges = []
    
    # Add Pillars
    for p_id, p_name in PILLARS.items():
        node_id = f"ZIG-PIL-{p_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_pillar",
            "name": f"{p_name} Pillar",
            "description": f"ZIG {p_name} Pillar",
            "url": ""
        })
        
    # Add Capabilities
    for c_id, c_name in capabilities.items():
        node_id = f"ZIG-CAP-{c_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_capability",
            "name": c_name,
            "description": f"ZIG Capability {c_id}",
            "url": ""
        })
        p_id = c_id.split('.')[0]
        edges.append({
            "source_id": node_id,
            "target_id": f"ZIG-PIL-{p_id}",
            "relationship_type": "belongs_to_pillar"
        })
        
    # Add Activities
    for a_id, a_name in activities.items():
        node_id = f"ZIG-ACT-{a_id}"
        nodes.append({
            "id": node_id,
            "type": "zig_activity",
            "name": a_name,
            "description": f"ZIG Activity {a_id}",
            "url": ""
        })
        c_id = ".".join(a_id.split('.')[:2])
        edges.append({
            "source_id": node_id,
            "target_id": f"ZIG-CAP-{c_id}",
            "relationship_type": "belongs_to_capability"
        })
        
    # Add Technologies
    for t_id, t_name in technologies.items():
        nodes.append({
            "id": t_id,
            "type": "zig_technology",
            "name": t_name,
            "description": f"ZIG Technology Mapping",
            "url": ""
        })
        
    # Add Tech Mappings
    for t_id, c_id in tech_mappings:
        # Note: some capabilities might not be parsed if they aren't in the PDFs 
        # but are in the tech mappings (e.g. Discovery phase might have missed some).
        # We will create edges regardless.
        edges.append({
            "source_id": t_id,
            "target_id": f"ZIG-CAP-{c_id}",
            "relationship_type": "implements_capability"
        })
        
    # Write nodes.csv
    with open('zig_nodes.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["id", "type", "name", "description", "url"])
        writer.writeheader()
        writer.writerows(nodes)
        
    # Write edges.csv
    with open('zig_edges.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["source_id", "target_id", "relationship_type"])
        writer.writeheader()
        writer.writerows(edges)
        
if __name__ == "__main__":
    txt_files = [
        "CTR_ZIG_DISCOVERY_PHASE.PDF.txt",
        "CTR_ZIG_PHASE_ONE.PDF.txt",
        "CTR_ZIG_PHASE_TWO.PDF.txt"
    ]
    caps, acts = parse_zig_text_files(txt_files)
    techs, mappings = parse_tech_mappings("zig_tech_mappings.txt")
    
    generate_csvs(caps, acts, techs, mappings)
    print(f"Parsed {len(caps)} capabilities and {len(acts)} activities.")
    print(f"Parsed {len(techs)} technologies with {len(mappings)} mappings.")
    print("Generated zig_nodes.csv and zig_edges.csv.")
