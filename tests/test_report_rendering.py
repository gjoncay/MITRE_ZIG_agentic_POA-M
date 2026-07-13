"""Regression coverage for complete human-readable analyst reports."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from consolidate_findings import build_context  # noqa: E402
from report_schema import _build_affected_hosts_table, render_markdown  # noqa: E402
from run_analyst_pipeline import _adapt_context_for_render, _llm_context  # noqa: E402


def _narrative() -> dict[str, str]:
    return {
        "threat_input_summary": "Complete evidence summary.",
        "exploitation_scenario": "Complete exploitation scenario.",
        "business_impact": "Complete business impact.",
        "immediate_action": "Immediate action.",
        "short_term_action": "Short-term action.",
        "long_term_action": "Long-term action.",
        "technology_implementation_notes": "Implementation notes.",
    }


def _mapping_context() -> dict:
    # Each CREF path intentionally stops at a different layer.  This mirrors
    # the graph's provenance-preserving path shape and used to produce false
    # "None found in graph" bullets in every incomplete path row.
    cref = [
        {
            "approach_id": "CREF-APP-1",
            "approach_name": "Dynamic Threat Awareness",
            "effect_id": "CREF-EFFECT-1",
            "effect_name": "Detect",
            "mapping_scope": "direct",
        },
        {
            "approach_id": "CREF-APP-1",
            "approach_name": "Dynamic Threat Awareness",
            "technique_id": "CREF-TECH-1",
            "technique_name": "Contextual Awareness",
            "mapping_scope": "direct",
        },
        {
            "approach_id": "CREF-APP-1",
            "approach_name": "Dynamic Threat Awareness",
            "technique_id": "CREF-TECH-1",
            "technique_name": "Contextual Awareness",
            "objective_id": "CREF-OBJ-1",
            "objective_name": "Prepare",
            "mapping_scope": "direct",
        },
        {
            "approach_id": "CREF-APP-1",
            "approach_name": "Dynamic Threat Awareness",
            "technique_id": "CREF-TECH-1",
            "technique_name": "Contextual Awareness",
            "objective_id": "CREF-OBJ-1",
            "objective_name": "Prepare",
            "goal_id": "CREF-GOAL-1",
            "goal_name": "Anticipate",
            "mapping_scope": "direct",
        },
    ]
    # More than the old 12-item display limit proves the final value remains
    # in the reviewer-facing Markdown rather than only in JSON/API output.
    for index in range(2, 15):
        cref.append(
            {
                "approach_id": f"CREF-APP-{index}",
                "approach_name": f"Approach {index}",
                "technique_id": f"CREF-TECH-{index}",
                "technique_name": f"Technique {index}",
                "objective_id": f"CREF-OBJ-{index}",
                "objective_name": f"Objective {index}",
                "goal_id": f"CREF-GOAL-{index}",
                "goal_name": f"Goal {index}",
                "effect_id": f"CREF-EFFECT-{index}",
                "effect_name": f"Effect {index}",
                "mapping_scope": "direct",
            }
        )

    return {
        "technique_id": "T0001",
        "technique_name": "Example Technique",
        "technique_description": "Example technique description.",
        "tactic": "[TA0001] Example Tactic",
        "affected_hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "host-1",
                "finding_text": "Example finding.",
                "severity": "High",
            }
        ],
        "finding_count": 1,
        "severity_breakdown": {"High": 1},
        "d3fend_countermeasures": [
            "[D3-1] Countermeasure 1",
            "[D3-2] Countermeasure 2",
            "[D3-3] Countermeasure 3",
        ],
        "d3fend_artifacts": [
            "[ART-1] Artifact 1",
            "[ART-2] Artifact 2",
            "[ART-3] Artifact 3",
            "[ART-4] Artifact 4",
        ],
        "mitre_analytics": [
            "[AN-1] Analytic 1",
            "[AN-2] Analytic 2",
            "[AN-3] Analytic 3",
        ],
        "mitre_mitigations": [
            "[M-1] Mitigation 1",
            "[M-2] Mitigation 2",
            "[M-3] Mitigation 3",
        ],
        "zig_technologies": [
            "[ZIG-TECH-1] Technology 1",
            "[ZIG-TECH-2] Technology 2",
            "[ZIG-TECH-3] Technology 3",
        ],
        "framework_mappings": {
            "zig": [
                {
                    "pillar_id": "ZIG-PILLAR-1",
                    "pillar_name": "Pillar 1",
                    "capability_id": "ZIG-CAP-1",
                    "capability_name": "Capability 1",
                    "activity_id": "ZIG-ACT-1",
                    "activity_name": "Activity 1",
                    "mapping_scope": "direct",
                }
            ],
            "cref": cref,
            "mitigations": [
                {
                    "mitigation_id": "M-1",
                    "mitigation_name": "Mitigation 1",
                    "nist_800_53_controls": ["AC-1"],
                    "zig_activity_ids": ["ZIG-ACT-1"],
                    "mapping_scope": "direct",
                }
            ],
            "csa": [
                {
                    "csa_id": "CSA-1",
                    "csa_name": "Control Access",
                    "mapping_scope": "direct",
                }
            ],
        },
    }


def test_markdown_keeps_all_mapping_values_and_filters_partial_cref_paths() -> None:
    context = _mapping_context()
    adapted = _adapt_context_for_render(
        context,
        {
            "csa_impact_summary": "Impact summary.",
            "architectural_recommendation": "Architectural recommendation.",
        },
    )

    resiliency_values = (
        adapted["cref_goal"],
        adapted["cref_objective"],
        adapted["cref_technique"],
        adapted["cref_approach"],
        adapted["cref_effect"],
    )
    assert all("None found in graph" not in value for value in resiliency_values)
    assert "[CREF-GOAL-14] Goal 14" in adapted["cref_goal"]
    assert "[AN-3] Analytic 3" in adapted["mitre_analytics"]
    assert "[M-3] Mitigation 3" in adapted["mitre_mitigations"]
    assert "[D3-3] Countermeasure 3" in adapted["d3fend_countermeasures_display"]
    assert "[ART-4] Artifact 4" in adapted["d3fend_artifacts"]
    assert "[ZIG-TECH-3] Technology 3" in adapted["zig_technologies_display"]

    template = (ROOT / "assessment_template_consolidated.md").read_text(encoding="utf-8")
    markdown = render_markdown(
        template,
        report_id="CONSOL-T0001",
        generated_date="2026-07-13",
        t_code="T0001",
        context=adapted,
        narrative=_narrative(),
        qa_result={"verdict": "PASS", "notes": "Complete."},
    )
    resiliency_chain = markdown.split("### Resiliency Chain", 1)[1].split(
        "### Architectural Recommendation", 1
    )[0]
    assert "None found in graph" not in resiliency_chain
    assert "[CREF-GOAL-14] Goal 14" in resiliency_chain
    assert "see JSON" not in markdown
    assert "see JSON/API" not in markdown


def test_source_observation_table_and_context_are_not_display_capped() -> None:
    hosts = [
        {
            "ip": "N/A",
            "hostname": "N/A",
            "finding_text": f"CTI observation {index}",
            "finding": f"CTI observation {index}",
            "severity": "Unknown",
        }
        for index in range(1, 52)
    ]
    group_data = {
        "technique_name": "Example Technique",
        "technique_description": "Example description.",
        "affected_hosts": hosts,
        "severity_breakdown": {"Unknown": len(hosts)},
    }
    context = build_context("T0001", group_data, {"tactic": "Example"})

    assert len(context["affected_hosts"]) == 51
    table = _build_affected_hosts_table({"affected_hosts": hosts, "_display_cap": 1})
    assert "CTI observation 1" in table
    assert "CTI observation 51" in table
    assert "see JSON" not in table


def test_complete_report_lists_remain_bounded_only_in_model_context() -> None:
    context = _mapping_context()
    context["zig_technologies"] = [f"[ZIG-TECH-{index}] Technology {index}" for index in range(1, 15)]

    model_context = _llm_context(context)

    assert len(model_context["zig_technologies"]) == 13
    assert model_context["zig_technologies"][-1]["_omitted_items"] == 2
