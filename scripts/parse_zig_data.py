"""Regenerate deterministic ZIG graph inputs from ``raw_data/zig``.

This parser is intentionally repository-relative: invoke it from the project
root, another shell directory, or automation without changing where the
outputs land.  It keeps every distinct technology-to-capability relationship;
exact triples repeated by a denormalized source export are normalized
deterministically without collapsing a different relationship type.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import tempfile
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parent.parent
RAW_ZIG_DIR = BASE_DIR / "raw_data" / "zig"
NODE_FIELDS = ("id", "type", "name", "description", "url")
EDGE_FIELDS = ("source_id", "target_id", "relationship_type")

PILLARS = {
    1: "User",
    2: "Device",
    3: "Application and Workload",
    4: "Data",
    5: "Network and Environment",
    6: "Automation and Orchestration",
    7: "Visibility and Analytics",
}


def _numeric_key(identifier: str) -> tuple[object, ...]:
    """Sort dotted IDs numerically while retaining a stable textual fallback."""
    parts: list[object] = []
    for part in str(identifier).split("."):
        parts.append(int(part) if part.isdigit() else part)
    return tuple(parts)


def _stage_csv(path: Path, fieldnames: Iterable[str], rows: Iterable[dict[str, str]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _replace_staged(staged: list[tuple[Path, Path]]) -> None:
    try:
        for target, temporary in staged:
            os.replace(temporary, target)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def _logical_edges(edges: Iterable[dict[str, str]]) -> tuple[list[dict[str, str]], int]:
    """Stable-deduplicate exact logical triples without using an edge set."""
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    repeated = 0
    for edge in edges:
        key = (edge["source_id"], edge["target_id"], edge["relationship_type"])
        if key in unique:
            repeated += 1
        else:
            unique[key] = edge
    return list(unique.values()), repeated


def parse_zig_text_files(files: Iterable[Path]) -> tuple[dict[str, str], dict[str, str]]:
    capabilities: dict[str, str] = {}
    activities: dict[str, str] = {}
    cap_pattern = re.compile(r"^Capability\s+(\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$")
    act_pattern = re.compile(r"^Activity\s+(\d+\.\d+\.\d+)\s+(.*?)(?:\s*\.*(?: \.*)*\s*\d+)?$")

    for path in files:
        if not path.is_file():
            print(f"Warning: ZIG source text is missing and will be skipped: {path}")
            continue
        with path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                capability_match = cap_pattern.search(line)
                if capability_match:
                    capability_id = capability_match.group(1)
                    capability_name = re.sub(r"\s*\.{2,}\s*\d*$", "", capability_match.group(2)).strip()
                    if capability_name and (
                        capability_id not in capabilities
                        or len(capability_name) > len(capabilities[capability_id])
                    ):
                        capabilities[capability_id] = capability_name

                activity_match = act_pattern.search(line)
                if activity_match:
                    activity_id = activity_match.group(1)
                    activity_name = re.sub(r"\s*\.{2,}\s*\d*$", "", activity_match.group(2)).strip()
                    if activity_name and (
                        activity_id not in activities
                        or len(activity_name) > len(activities[activity_id])
                    ):
                        activities[activity_id] = activity_name
    return capabilities, activities


def parse_tech_mappings(path: Path) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Parse the three-line technology/capability blocks without deduplicating mappings."""
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    technologies: dict[str, str] = {}
    mappings: list[tuple[str, str]] = []
    technology_counter = 1
    index = 0
    while index < len(lines):
        technology_name = lines[index].strip()
        if not technology_name:
            index += 1
            continue
        if index + 1 >= len(lines):
            break
        capability_line = lines[index + 1].strip()
        technology_id = f"ZIG-TECH-{technology_counter}"
        technologies[technology_id] = technology_name
        technology_counter += 1
        # Examples are packed as ``4.4P4 5.1P5`` or ``4.4P45.1P5``.
        for capability_id in re.findall(r"(\d+\.\d+)P\d", capability_line):
            mappings.append((technology_id, capability_id))
        index += 3
    return technologies, mappings


def generate_records(
    capabilities: dict[str, str],
    activities: dict[str, str],
    technologies: dict[str, str],
    technology_mappings: list[tuple[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Materialize valid graph records in deterministic order.

    The source mapping list is not converted to a set.  Exact logical triples
    are normalized only after all derived rows have been collected, leaving
    distinct relationship types between the same node pair intact.
    """
    capabilities = dict(capabilities)
    referenced_capabilities = {capability_id for _, capability_id in technology_mappings}
    referenced_capabilities.update(".".join(activity_id.split(".")[:2]) for activity_id in activities)
    for capability_id in sorted(referenced_capabilities, key=_numeric_key):
        # Preserve the raw mapping while ensuring no edge points at a phantom
        # node.  CREF reconciliation can replace these conservative labels.
        capabilities.setdefault(capability_id, f"ZIG Capability {capability_id} (source mapping)")

    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    for pillar_id, pillar_name in sorted(PILLARS.items()):
        nodes.append(
            {
                "id": f"ZIG-PIL-{pillar_id}",
                "type": "zig_pillar",
                "name": f"{pillar_name} Pillar",
                "description": f"ZIG {pillar_name} Pillar",
                "url": "",
            }
        )
    for capability_id in sorted(capabilities, key=_numeric_key):
        node_id = f"ZIG-CAP-{capability_id}"
        nodes.append(
            {
                "id": node_id,
                "type": "zig_capability",
                "name": capabilities[capability_id],
                "description": f"ZIG Capability {capability_id}",
                "url": "",
            }
        )
        pillar_id = capability_id.split(".", 1)[0]
        if pillar_id.isdigit() and int(pillar_id) in PILLARS:
            edges.append(
                {
                    "source_id": node_id,
                    "target_id": f"ZIG-PIL-{pillar_id}",
                    "relationship_type": "belongs_to_pillar",
                }
            )
    for activity_id in sorted(activities, key=_numeric_key):
        node_id = f"ZIG-ACT-{activity_id}"
        nodes.append(
            {
                "id": node_id,
                "type": "zig_activity",
                "name": activities[activity_id],
                "description": f"ZIG Activity {activity_id}",
                "url": "",
            }
        )
        capability_id = ".".join(activity_id.split(".")[:2])
        edges.append(
            {
                "source_id": node_id,
                "target_id": f"ZIG-CAP-{capability_id}",
                "relationship_type": "belongs_to_capability",
            }
        )
    for technology_id in sorted(technologies, key=lambda value: int(value.rsplit("-", 1)[1])):
        nodes.append(
            {
                "id": technology_id,
                "type": "zig_technology",
                "name": technologies[technology_id],
                "description": "ZIG Technology Mapping",
                "url": "",
            }
        )
    for technology_id, capability_id in technology_mappings:
        edges.append(
            {
                "source_id": technology_id,
                "target_id": f"ZIG-CAP-{capability_id}",
                "relationship_type": "implements_capability",
            }
        )

    logical_edges, _ = _logical_edges(edges)
    return sorted(nodes, key=lambda node: node["id"]), sorted(
        logical_edges,
        key=lambda edge: (edge["source_id"], edge["target_id"], edge["relationship_type"]),
    )


def generate_csvs(
    capabilities: dict[str, str],
    activities: dict[str, str],
    technologies: dict[str, str],
    technology_mappings: list[tuple[str, str]],
    *,
    output_dir: Path = BASE_DIR,
) -> tuple[int, int]:
    nodes, edges = generate_records(capabilities, activities, technologies, technology_mappings)
    staged = [
        (output_dir / "zig_nodes.csv", _stage_csv(output_dir / "zig_nodes.csv", NODE_FIELDS, nodes)),
        (output_dir / "zig_edges.csv", _stage_csv(output_dir / "zig_edges.csv", EDGE_FIELDS, edges)),
    ]
    _replace_staged(staged)
    return len(nodes), len(edges)


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate ZIG graph CSVs from raw_data/zig.")
    parser.add_argument("--base-dir", type=Path, default=BASE_DIR, help="Repository root.")
    args = parser.parse_args()
    base_dir = args.base_dir.resolve()
    raw_dir = base_dir / "raw_data" / "zig"
    text_files = [
        raw_dir / "CTR_ZIG_DISCOVERY_PHASE.PDF.txt",
        raw_dir / "CTR_ZIG_PHASE_ONE.PDF.txt",
        raw_dir / "CTR_ZIG_PHASE_TWO.PDF.txt",
    ]
    capabilities, activities = parse_zig_text_files(text_files)
    technologies, mappings = parse_tech_mappings(raw_dir / "zig_tech_mappings.txt")
    node_count, edge_count = generate_csvs(
        capabilities, activities, technologies, mappings, output_dir=base_dir
    )
    print(f"Parsed {len(capabilities)} capabilities and {len(activities)} activities.")
    print(f"Parsed {len(technologies)} technologies with {len(mappings)} mapping rows.")
    print(f"Generated {node_count} nodes and {edge_count} edge rows in {base_dir}.")


if __name__ == "__main__":
    main()
