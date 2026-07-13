"""Evidence-first mapping regression tests.

These tests use the real, manifest-validated graph but no embedding model or
network provider.  They protect the core requirement that one threat-intel
observation may legitimately yield several distinct ATT&CK report groups.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from consolidate_findings import group_findings_by_technique  # noqa: E402
from graph_engine import KnowledgeGraphEngine  # noqa: E402


def test_one_explicit_threat_intel_observation_can_yield_six_ttp_groups() -> None:
    engine = KnowledgeGraphEngine(ROOT, load_embeddings=False)
    ids = ["T1190", "T1135", "T1685", "T1036.005", "T1003", "T1566"]
    frame = pd.DataFrame([
        {
            "_sheet": "text_chunk",
            "_source_row": "1",
            "Finding": "Campaign behavior explicitly references " + ", ".join(ids) + ".",
            "Severity": "High",
            "IP": "N/A",
            "Hostname": "N/A",
        }
    ])

    groups, unresolved = group_findings_by_technique(engine, frame)

    assert unresolved == 0
    assert set(groups) == set(ids)
    assert all(len(groups[technique_id]["affected_hosts"]) == 1 for technique_id in ids)
    assert {
        group["affected_hosts"][0]["resolution_method"]
        for group in groups.values()
    } == {"explicit_attack_id"}
    assert {
        (item["source_locator"]["sheet"], item["source_locator"]["row"])
        for group in groups.values()
        for item in group["affected_hosts"]
    } == {("text_chunk", "1")}


def test_lowercase_explicit_threat_intel_ids_preserve_all_six_ttp_groups() -> None:
    engine = KnowledgeGraphEngine(ROOT, load_embeddings=False)
    ids = ["T1190", "T1135", "T1685", "T1036.005", "T1003", "T1566"]
    frame = pd.DataFrame([
        {
            "Finding": "CTI feed used lowercase IDs: " + ", ".join(item.lower() for item in ids),
            "Severity": "High",
        }
    ])

    groups, unresolved = group_findings_by_technique(engine, frame)

    assert unresolved == 0
    assert set(groups) == set(ids)
    assert {
        group["affected_hosts"][0]["resolution_method"]
        for group in groups.values()
    } == {"explicit_attack_id"}


def test_canonical_name_matching_prefers_the_specific_subtechnique() -> None:
    engine = KnowledgeGraphEngine(ROOT, load_embeddings=False)
    # The exact sub-technique phrase must not additionally create its parent
    # when both canonical names are present in ATT&CK's vocabulary.
    matches = engine.match_attack_technique_names("The actor used Masquerading: Match Legitimate Resource Name or Location.")

    assert "T1036.005" in matches
    assert "T1036" not in matches
