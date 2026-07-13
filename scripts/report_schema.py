"""
report_schema.py

Shared schema/rendering layer for the CONSOLIDATED (many-hosts-per-technique)
assessment report pipeline. This module is intentionally self-contained: it
does not import graph_engine, agent_batch_processor, or any QA module, so it
can be developed and tested independently of those other pieces.

Two entry points:

  build_report_json(t_code, context, narrative, qa_result)
      -> plain, JSON-serializable dict mirroring every field that ends up in
         the rendered markdown, PLUS the full (uncapped) affected_hosts list
         for machine consumption.

  render_markdown(template_str, report_id, generated_date, t_code, context,
                   narrative, qa_result)
      -> the filled assessment_template_consolidated.md markdown string.

Expected shapes of the four "data" arguments (all caller-supplied; this
module never calls datetime.now() or any graph/QA code itself):

  context: dict, technique-level facts pulled from the knowledge graph, e.g.
      {
        "technique_name": str,
        "tactic": str,
        "technique_description": str,
        "mitre_analytics": str,
        "mitre_mitigations": str,
        "d3fend_countermeasure_1": str,
        "d3fend_countermeasure_2": str,
        "d3fend_artifacts": str,
        "zig_pillar_name": str,
        "zig_capability_id": str,
        "zig_capability_name": str,
        "zig_activity_1": str,
        "zig_technology_1": str,
        "zig_technology_2": str,
        "cref_goal": str,
        "cref_objective": str,
        "cref_technique": str,
        "cref_approach": str,
        "cref_effect": str,
        "cref_recommendation": str,
        "cref_mitigation_id": str,
        "cref_mitigation_name": str,
        "nist_800_53_controls": str,
        "traceability": str,
        "csa_name": str,
        "csa_impact_summary": str,
        "finding_count": int,                     # optional; derived from
                                                    # len(affected_hosts) if
                                                    # omitted
        "severity_breakdown": {"Critical": 3, "High": 9, ...},
        "affected_hosts": [
            {"ip": "10.0.0.5", "hostname": "web01",
             "finding": "...", "severity": "Critical"},
            ...
        ],
        "_display_cap": 50,                        # optional, markdown-only
        "report_id": str,                           # read by
        "generated_date": str,                      # build_report_json only
                                                      # (render_markdown gets
                                                      # these as explicit args
                                                      # instead)
      }

  narrative: dict, the 7 agent-authored "So What" / POA&M / implementation
      fields that are NOT pulled from the graph:
      {
        "threat_input_summary": str,
        "exploitation_scenario": str,
        "business_impact": str,
        "immediate_action": str,
        "short_term_action": str,
        "long_term_action": str,
        "technology_implementation_notes": str,
      }

  qa_result: dict, the automated QA pass's verdict:
      {"verdict": "PASS" | "FLAG", "notes": str}
"""

import os
import re
import html

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(BASE_DIR, "assessment_template_consolidated.md")


def build_report_json(t_code, context, narrative, qa_result):
    """Pure function of its inputs -> plain, JSON-serializable dict.

    Does NOT generate report_id/generated_date itself: both are read from
    context (caller-supplied) so this function stays a pure function of
    (t_code, context, narrative, qa_result) with no hidden clock/ID calls.
    """
    affected_hosts = context.get("affected_hosts", [])
    finding_count = context.get("finding_count", len(affected_hosts))

    return {
        # Identity / provenance (caller-supplied, never generated here)
        "report_id": context.get("report_id"),
        "generated_date": context.get("generated_date"),

        # MITRE technique-level identity
        "technique_id": t_code,
        "technique_name": context.get("technique_name"),
        "tactic": context.get("tactic"),
        "technique_description": context.get("technique_description"),
        "mitre_analytics": context.get("mitre_analytics"),
        "mitre_mitigations": context.get("mitre_mitigations"),

        # Scope of this consolidated report
        "finding_count": finding_count,
        "severity_breakdown": context.get("severity_breakdown", {}),
        "affected_hosts": affected_hosts,  # full list, not capped
        "is_hostless": _is_hostless(affected_hosts),  # True for CTI/adversary narrative input, no real asset data
        # Exhaustive, deterministic graph relationships. Markdown presents a
        # concise primary view; this preserves every one-to-many framework
        # mapping for APIs, exports, and downstream analysis.
        "framework_mappings": context.get("framework_mappings", {}),

        # D3FEND
        "d3fend_countermeasure_1": context.get("d3fend_countermeasure_1"),
        "d3fend_countermeasure_2": context.get("d3fend_countermeasure_2"),
        "d3fend_artifacts": context.get("d3fend_artifacts"),

        # ZIG
        "zig_pillar_name": context.get("zig_pillar_name"),
        "zig_capability_id": context.get("zig_capability_id"),
        "zig_capability_name": context.get("zig_capability_name"),
        "zig_activity_1": context.get("zig_activity_1"),
        "zig_technology_1": context.get("zig_technology_1"),
        "zig_technology_2": context.get("zig_technology_2"),

        # CREF
        "cref_goal": context.get("cref_goal"),
        "cref_objective": context.get("cref_objective"),
        "cref_technique": context.get("cref_technique"),
        "cref_approach": context.get("cref_approach"),
        "cref_effect": context.get("cref_effect"),
        "cref_recommendation": context.get("cref_recommendation"),
        "cref_mitigation_id": context.get("cref_mitigation_id"),
        "cref_mitigation_name": context.get("cref_mitigation_name"),

        # NIST SP 800-53
        "nist_800_53_controls": context.get("nist_800_53_controls"),
        "traceability": context.get("traceability"),

        # CSA (mission-level framing)
        "csa_name": context.get("csa_name"),
        "csa_impact_summary": context.get("csa_impact_summary"),

        # Narrative (agent-authored) fields
        "threat_input_summary": narrative.get("threat_input_summary"),
        "exploitation_scenario": narrative.get("exploitation_scenario"),
        "business_impact": narrative.get("business_impact"),
        "immediate_action": narrative.get("immediate_action"),
        "short_term_action": narrative.get("short_term_action"),
        "long_term_action": narrative.get("long_term_action"),
        "technology_implementation_notes": narrative.get(
            "technology_implementation_notes"
        ),

        # QA/QC
        "qa_verdict": qa_result.get("verdict"),
        "qa_notes": qa_result.get("notes"),
    }


def _is_hostless(affected_hosts):
    """True when NEITHER ip nor hostname is real for ANY row -- i.e. this
    report came from CTI/threat-actor narrative text rather than a
    network/vuln-scan finding tied to actual assets. Rendering an IP/Hostname
    table full of "N/A" in that case is actively misleading (it implies asset
    context that doesn't exist), so the caller uses a different table shape
    and section label for this case.
    """
    if not affected_hosts:
        return False
    return all(
        (h.get("ip") or "N/A") in ("N/A", "") and (h.get("hostname") or "N/A") in ("N/A", "")
        for h in affected_hosts
    )


def _host_context_label(affected_hosts):
    """Section label for {HOST_CONTEXT_LABEL} -- "Affected Hosts" only makes
    sense when there's real asset data; otherwise this is CTI/adversary
    narrative describing behavior, not a host inventory."""
    return "Source Observations" if _is_hostless(affected_hosts) else "Affected Hosts"


def _build_affected_hosts_table(context):
    """Render the {AFFECTED_HOSTS_TABLE} markdown table, capped for display.

    Full data always lives in build_report_json()'s uncapped affected_hosts
    list -- the cap here is purely about keeping the markdown report
    readable. When every row is host-less (see _is_hostless), drops the
    IP/Hostname columns entirely and dedupes identical excerpts instead of
    repeating an "N/A | N/A" pair per row.
    """
    affected_hosts = context.get("affected_hosts", [])
    display_cap = context.get("_display_cap", 50)
    finding_count = context.get("finding_count", len(affected_hosts))

    if _is_hostless(affected_hosts):
        seen = []
        for host in affected_hosts:
            excerpt = host.get("finding", "N/A")
            if excerpt not in seen:
                seen.append(excerpt)
        displayed = seen[:display_cap]

        lines = ["| Source Excerpt | Severity |", "|---|---|"]
        excerpt_to_severity = {h.get("finding", "N/A"): h.get("severity", "N/A") for h in affected_hosts}
        for excerpt in displayed:
            lines.append(
                f"| {_escape_table_cell(excerpt)} | "
                f"{_escape_table_cell(excerpt_to_severity.get(excerpt, 'N/A'))} |"
            )

        if len(seen) > len(displayed):
            remaining = len(seen) - len(displayed)
            lines.append("")
            lines.append(f"*...and {remaining} more excerpt(s) (see JSON for full list)*")

        return "\n".join(lines)

    displayed = affected_hosts[:display_cap]

    lines = ["| IP | Hostname | Finding | Severity |", "|---|---|---|---|"]
    for host in displayed:
        lines.append(
            "| {ip} | {hostname} | {finding} | {severity} |".format(
                ip=_escape_table_cell(host.get("ip", "N/A")),
                hostname=_escape_table_cell(host.get("hostname", "N/A")),
                finding=_escape_table_cell(host.get("finding", "N/A")),
                severity=_escape_table_cell(host.get("severity", "N/A")),
            )
        )

    if finding_count > len(displayed):
        remaining = finding_count - len(displayed)
        lines.append("")
        lines.append(
            f"*...and {remaining} more hosts (see JSON for full list)*"
        )

    return "\n".join(lines)


def _escape_table_cell(value):
    """Make untrusted artifact text safe inside a Markdown table cell.

    Python-Markdown passes raw HTML through to the PDF renderer. Escaping here
    protects the common high-risk path (finding, host, severity, and source
    excerpt) and also prevents an embedded pipe from changing table shape.
    """
    text = html.escape(str(value if value is not None else "N/A"), quote=False)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _build_severity_breakdown_str(context):
    """Render {SEVERITY_BREAKDOWN} as a comma-joined "Level: count" string."""
    severity_breakdown = context.get("severity_breakdown", {})
    return ", ".join(
        f"{level}: {count}" for level, count in severity_breakdown.items()
    )


def render_markdown(
    template_str, report_id, generated_date, t_code, context, narrative, qa_result
):
    """Fill every placeholder in assessment_template_consolidated.md.

    If a placeholder in template_str has no matching kwarg below, str.format
    raises KeyError -- that is intentional and is left to propagate. A
    mismatched placeholder is a real bug (template and renderer drifted
    apart) and must surface loudly rather than being swallowed.
    """
    affected_hosts_table = _build_affected_hosts_table(context)
    severity_breakdown_str = _build_severity_breakdown_str(context)
    finding_count = context.get("finding_count", len(context.get("affected_hosts", [])))
    host_context_label = _host_context_label(context.get("affected_hosts", []))

    return template_str.format(
        DATE=generated_date,
        ASSESSMENT_ID=report_id,
        FINDING_COUNT=finding_count,
        SEVERITY_BREAKDOWN=severity_breakdown_str,
        HOST_CONTEXT_LABEL=host_context_label,
        THREAT_INPUT_SUMMARY=narrative["threat_input_summary"],
        AFFECTED_HOSTS_TABLE=affected_hosts_table,
        EXPLOITATION_SCENARIO=narrative["exploitation_scenario"],
        BUSINESS_IMPACT=narrative["business_impact"],
        CSA_NAME=context["csa_name"],
        CSA_IMPACT_SUMMARY=context["csa_impact_summary"],
        MITRE_TACTIC=context["tactic"],
        MITRE_TECHNIQUE_ID=t_code,
        MITRE_TECHNIQUE_NAME=context["technique_name"],
        MITRE_TECHNIQUE_DESCRIPTION=context["technique_description"],
        MITRE_ANALYTICS=context["mitre_analytics"],
        MITRE_MITIGATIONS=context["mitre_mitigations"],
        D3FEND_COUNTERMEASURE_1=context["d3fend_countermeasure_1"],
        D3FEND_COUNTERMEASURE_2=context["d3fend_countermeasure_2"],
        D3FEND_ARTIFACTS=context["d3fend_artifacts"],
        ZIG_PILLAR_NAME=context["zig_pillar_name"],
        ZIG_CAPABILITY_ID=context["zig_capability_id"],
        ZIG_CAPABILITY_NAME=context["zig_capability_name"],
        ZIG_ACTIVITY_1=context["zig_activity_1"],
        CREF_GOAL=context["cref_goal"],
        CREF_OBJECTIVE=context["cref_objective"],
        CREF_TECHNIQUE=context["cref_technique"],
        CREF_APPROACH=context["cref_approach"],
        CREF_EFFECT=context["cref_effect"],
        CREF_RECOMMENDATION=context["cref_recommendation"],
        CREF_MITIGATION_ID=context["cref_mitigation_id"],
        CREF_MITIGATION_NAME=context["cref_mitigation_name"],
        NIST_800_53_CONTROLS=context["nist_800_53_controls"],
        TRACEABILITY=context["traceability"],
        ZIG_TECHNOLOGY_1=context["zig_technology_1"],
        ZIG_TECHNOLOGY_2=context["zig_technology_2"],
        TECHNOLOGY_IMPLEMENTATION_NOTES=narrative["technology_implementation_notes"],
        IMMEDIATE_ACTION=narrative["immediate_action"],
        SHORT_TERM_ACTION=narrative["short_term_action"],
        LONG_TERM_ACTION=narrative["long_term_action"],
        QA_VERDICT=qa_result["verdict"],
        QA_NOTES=qa_result["notes"],
    )


def _extract_placeholder_names(template_str):
    """Return the sorted, de-duplicated {PLACEHOLDER} names used in a template."""
    return sorted(set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template_str)))


if __name__ == "__main__":
    # --- Hand-built fake inputs (no dependency on graph_engine / QA module) ---
    fake_t_code = "T1558.001"

    fake_context = {
        "technique_name": "Golden Ticket",
        "tactic": "[TA0006] Credential Access",
        "technique_description": "Adversaries who have the Kerberos ticket-"
        "granting ticket (TGT) hash may forge Kerberos tickets.",
        "mitre_analytics": "  - [AN0031] Unusual TGT request volume",
        "mitre_mitigations": "  - [M1015] Active Directory Configuration",
        "d3fend_countermeasure_1": "[D3-CRO] Credential Rotation",
        "d3fend_countermeasure_2": "[D3-AL] Audit Log Analysis",
        "d3fend_artifacts": "[DC0001] Active Directory, [DC0002] Kerberos Ticket",
        "zig_pillar_name": "Identity",
        "zig_capability_id": "1.2",
        "zig_capability_name": "Identity Federation & User Credentialing",
        "zig_activity_1": "[ACT-1.2.3] Enforce Kerberos pre-authentication",
        "zig_technology_1": "[TECH-01] Privileged Access Management",
        "zig_technology_2": "[TECH-02] LAPS",
        "cref_goal": "Recover",
        "cref_objective": "Reduce recovery time",
        "cref_technique": "Non-Persistence",
        "cref_approach": "Non-Persistent Information",
        "cref_effect": "Contain",
        "cref_recommendation": "Because Golden Ticket attacks can recur in "
        "forms tactical controls won't catch, engineer for non-persistent "
        "credential material (recover the mission) rather than relying "
        "solely on tactical blockers alone.",
        "cref_mitigation_id": "CM0042",
        "cref_mitigation_name": "Credential Lifetime Reduction",
        "nist_800_53_controls": "AC-4(3), IA-5(13)",
        "traceability": "Implements CREF Approach CA0017 / ZIG Activity ACT-1.2.3",
        "csa_name": "Control Access",
        "csa_impact_summary": "This finding threatens the ability to control "
        "access to mission systems.",
        "finding_count": 14,
        "severity_breakdown": {"Critical": 3, "High": 9, "Medium": 2},
        "affected_hosts": [
            {
                "ip": "10.1.1.5",
                "hostname": "dc01",
                "finding": "Unconstrained delegation enabled",
                "severity": "Critical",
            },
            {
                "ip": "10.1.1.6",
                "hostname": "dc02",
                "finding": "Unconstrained delegation enabled",
                "severity": "Critical",
            },
            {
                "ip": "10.1.2.10",
                "hostname": "app03",
                "finding": "Weak Kerberos pre-auth config",
                "severity": "High",
            },
        ],
        "_display_cap": 2,  # deliberately small, to exercise the "N more" path
        "report_id": "ASMT-CONSOL-0001",
        "generated_date": "2026-07-12",
    }

    fake_narrative = {
        "threat_input_summary": "14 hosts across the domain resolved to "
        "Golden Ticket / forged Kerberos ticket behavior.",
        "exploitation_scenario": "An adversary with the krbtgt hash can "
        "forge TGTs offline and impersonate any account domain-wide.",
        "business_impact": "Complete domain compromise across all listed hosts.",
        "immediate_action": "Rotate the krbtgt password (twice) and audit "
        "unconstrained delegation on every host listed above.",
        "short_term_action": "Deploy continuous monitoring for anomalous "
        "TGT requests across all affected hosts.",
        "long_term_action": "Adopt non-persistent credential architecture "
        "per Section 4 across the affected host population.",
        "technology_implementation_notes": "Ensure configurations align "
        "with vendor security baselines on every affected host.",
    }

    fake_qa_result = {
        "verdict": "PASS",
        "notes": "All 14 findings mapped to T1558.001 with graph-sourced "
        "D3FEND/ZIG/CREF/NIST fields; no fabricated identifiers detected.",
    }

    report_json = build_report_json(
        fake_t_code, fake_context, fake_narrative, fake_qa_result
    )
    assert report_json["technique_id"] == fake_t_code
    assert report_json["finding_count"] == 14
    assert len(report_json["affected_hosts"]) == 3  # uncapped, machine list
    assert report_json["report_id"] == "ASMT-CONSOL-0001"
    print("build_report_json: OK ->", len(report_json), "fields")

    with open(TEMPLATE_PATH, "r") as f:
        template_str = f.read()

    markdown = render_markdown(
        template_str,
        report_id="ASMT-CONSOL-0001",
        generated_date="2026-07-12",
        t_code=fake_t_code,
        context=fake_context,
        narrative=fake_narrative,
        qa_result=fake_qa_result,
    )
    assert "T1558.001" in markdown
    assert "...and 12 more hosts (see JSON for full list)" in markdown
    assert "Critical: 3, High: 9, Medium: 2" in markdown
    print("render_markdown: OK ->", len(markdown), "chars")

    placeholder_names = _extract_placeholder_names(template_str)
    print(f"\nTemplate placeholder names ({len(placeholder_names)}):")
    for name in placeholder_names:
        print(f"  - {name}")

    print("\nSmoke test passed.")
