import json
import os

try:
    from openai import OpenAI
    OPENAI_ENABLED = True
except ImportError:
    OPENAI_ENABLED = False

try:
    import google.generativeai as genai
    GEMINI_ENABLED = True
except ImportError:
    GEMINI_ENABLED = False

NARRATIVE_KEYS = [
    'exploitation_scenario', 'business_impact', 'csa_impact_summary',
    'architectural_recommendation', 'immediate_action', 'short_term_action',
    'long_term_action'
]

JSON_ONLY_CORRECTION = (
    "Your previous response could not be parsed as JSON. "
    "Reply with valid JSON only -- no markdown fences, no commentary, no leading or trailing text."
)


def _empty_narrative():
    return {k: "" for k in NARRATIVE_KEYS}


def _safe_qa_default(reason):
    return {"verdict": "FLAG", "notes": f"QA call failed: {reason}"}


def _build_narrative_prompt(context):
    ctx = context or {}
    facts = json.dumps(ctx, indent=2, default=str)
    return (
        "You are a senior cyber threat analyst writing an assessment report section. "
        "Using ONLY the graph facts supplied below (MITRE ATT&CK, D3FEND, ZIG/Zero Trust, "
        "CREF, NIST, and CSA data), write a professional narrative for a defense customer.\n\n"
        "Graph facts:\n"
        f"{facts}\n\n"
        "Respond with ONLY a JSON object with exactly these 7 string keys, no others:\n"
        f"{json.dumps(NARRATIVE_KEYS)}\n\n"
        "- exploitation_scenario: how an adversary would exploit this technique against the affected hosts.\n"
        "- business_impact: the operational/mission consequence if exploited.\n"
        "- csa_impact_summary: impact framed against the supplied Cyber Survivability Attribute (csa_name).\n"
        "- architectural_recommendation: a recommendation grounded in the supplied CREF approach/goal.\n"
        "- immediate_action: a specific, actionable near-term remediation step.\n"
        "- short_term_action: a specific short-term (weeks) remediation step.\n"
        "- long_term_action: a specific long-term architectural remediation step.\n\n"
        "Do not invent framework IDs that are not present in the supplied facts. "
        "No markdown fences, no commentary -- JSON only."
    )


def _build_proofread_prompt(markdown_text):
    return (
        "You are a technical editor proofreading a cybersecurity assessment report written in Markdown. "
        "Fix grammar, typos, spacing, and prose consistency ONLY.\n\n"
        "Strict rules:\n"
        "- Do NOT invent, remove, or alter any MITRE/D3FEND/ZIG/CREF/NIST/CSA identifiers.\n"
        "- Do NOT change the text inside any bracketed [ID] tokens.\n"
        "- Do NOT alter the POA&M checkboxes (e.g. '- [ ]' / '- [x]').\n"
        "- Do NOT add or remove any factual content, sections, or headings.\n\n"
        "Return ONLY the corrected Markdown document -- no commentary, no code fences.\n\n"
        "--- DOCUMENT START ---\n"
        f"{markdown_text}\n"
        "--- DOCUMENT END ---"
    )


def _build_qa_prompt(markdown_text, context):
    ctx = context or {}
    facts = json.dumps(ctx, indent=2, default=str)
    return (
        "You are a QA/QC reviewer checking a cybersecurity assessment report before it ships. "
        "You are given the report Markdown and the graph facts it was generated from.\n\n"
        "Graph facts:\n"
        f"{facts}\n\n"
        "Report:\n"
        f"{markdown_text}\n\n"
        "Check:\n"
        "1. Does the exploitation scenario logically follow from technique_name/technique_description?\n"
        "2. Does the severity framing look reasonable given the supplied findings?\n"
        "3. Is the POA&M (immediate/short-term/long-term actions) actionable and specific, not generic filler?\n"
        "4. Are there any obviously invented-sounding framework IDs not present in the supplied context?\n\n"
        "Respond with ONLY a JSON object: {\"verdict\": \"PASS\" or \"FLAG\", \"notes\": \"...\"}. "
        "No markdown fences, no commentary."
    )


def _parse_json_object(text):
    if text is None:
        return None
    cleaned = text.strip()
    if cleaned.startswith('```'):
        cleaned = cleaned.strip('`')
        if cleaned.lower().startswith('json'):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        return None


class LLMProvider:
    def draft_narrative(self, context: dict) -> dict:
        """Drafts the 7-field narrative section of a report from graph facts."""
        raise NotImplementedError

    def proofread(self, markdown_text: str) -> str:
        """Cleans grammar/prose in a report without touching identifiers or checkboxes."""
        raise NotImplementedError

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        """Reviews a drafted report for logical/factual soundness."""
        raise NotImplementedError


class _ChatCompletionMixin:
    """Shared draft/proofread/qa logic for providers that expose a single _complete(prompt) call."""

    def _complete(self, prompt: str) -> str:
        raise NotImplementedError

    def draft_narrative(self, context: dict) -> dict:
        prompt = _build_narrative_prompt(context)
        try:
            raw = self._complete(prompt)
        except Exception:
            # A runtime failure (e.g. the configured server is unreachable) should degrade
            # to legible heuristic text, not blank fields -- missing-package/key failures
            # are already caught earlier in get_provider(); this is the network/runtime case.
            return HeuristicFallbackProvider().draft_narrative(context)

        parsed = _parse_json_object(raw)
        if parsed is None:
            try:
                raw = self._complete(prompt + "\n\n" + JSON_ONLY_CORRECTION)
                parsed = _parse_json_object(raw)
            except Exception:
                parsed = None

        if not isinstance(parsed, dict):
            return HeuristicFallbackProvider().draft_narrative(context)

        return {k: str(parsed.get(k, "")) for k in NARRATIVE_KEYS}

    def proofread(self, markdown_text: str) -> str:
        try:
            result = self._complete(_build_proofread_prompt(markdown_text))
            return result if result else markdown_text
        except Exception:
            return markdown_text

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        prompt = _build_qa_prompt(markdown_text, context)
        try:
            raw = self._complete(prompt)
        except Exception as e:
            return _safe_qa_default(str(e))

        parsed = _parse_json_object(raw)
        if parsed is None:
            try:
                raw = self._complete(prompt + "\n\n" + JSON_ONLY_CORRECTION)
                parsed = _parse_json_object(raw)
            except Exception as e:
                return _safe_qa_default(str(e))

        if not isinstance(parsed, dict) or 'verdict' not in parsed:
            return _safe_qa_default("response was not valid JSON with a verdict field")

        verdict = parsed.get('verdict')
        if verdict not in ('PASS', 'FLAG'):
            verdict = 'FLAG'
        return {"verdict": verdict, "notes": str(parsed.get('notes', ''))}


class LocalOpenAICompatProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to any local server exposing the OpenAI chat-completions API (Ollama, LM Studio, vLLM, llama.cpp)."""

    def __init__(self):
        if not OPENAI_ENABLED:
            raise ImportError("The 'openai' package is required for LocalOpenAICompatProvider.")
        self.base_url = os.environ.get('LOCAL_LLM_BASE_URL', 'http://localhost:11434/v1')
        self.api_key = os.environ.get('LOCAL_LLM_API_KEY', 'not-needed')
        self.model = os.environ.get('LOCAL_LLM_MODEL', 'llama3.1')
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)

    def _complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class OpenAIProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to the hosted OpenAI API."""

    def __init__(self):
        if not OPENAI_ENABLED:
            raise ImportError("The 'openai' package is required for OpenAIProvider.")
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        self.model = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')
        self.client = OpenAI(api_key=api_key)

    def _complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class GeminiProvider(_ChatCompletionMixin, LLMProvider):
    """Talks to the hosted Google Gemini API."""

    def __init__(self):
        if not GEMINI_ENABLED:
            raise ImportError("The 'google-generativeai' package is required for GeminiProvider.")
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        self.model_name = os.environ.get('GEMINI_MODEL', 'gemini-1.5-flash')
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(self.model_name)

    def _complete(self, prompt: str) -> str:
        response = self.model.generate_content(prompt)
        return response.text


# Sentinel strings crawl_correlation() (scripts/consolidate_findings.py) and
# agent_batch_processor.py return in place of a real name when the graph has
# no match for a given field -- they are never empty/None, so a plain
# truthiness check (`if csa_name:`) is always true and can't detect "nothing
# found". _is_unresolved() treats these (plus None/empty) as "nothing found".
_UNRESOLVED_MARKERS = {"None found in graph", "No matching ZIG activity"}


def _is_unresolved(value):
    return not value or value in _UNRESOLVED_MARKERS


class HeuristicFallbackProvider(LLMProvider):
    """Deterministic, network-free provider -- the air-gapped-safe default when no LLM is configured."""

    def draft_narrative(self, context: dict) -> dict:
        ctx = context or {}
        finding_text = ""
        affected_hosts = ctx.get('affected_hosts') or []
        if affected_hosts:
            finding_text = str(affected_hosts[0].get('finding_text', '') or '')
        hostname = affected_hosts[0].get('hostname', 'the affected host') if affected_hosts else 'the affected host'
        ip = affected_hosts[0].get('ip', 'N/A') if affected_hosts else 'N/A'

        if "Kerberos" in finding_text or "Delegation" in finding_text:
            exploitation = ("An adversary can request authentication tickets offline and crack them, "
                             "or use unconstrained delegation to impersonate highly privileged users "
                             "across the domain.")
            impact = "Complete domain compromise, unauthorized access to all Active Directory integrated services."
            imm_action = f"Disable unconstrained delegation or enforce Kerberos Pre-Auth on {hostname} ({ip})."
        elif "password" in finding_text.lower():
            exploitation = ("Adversaries can easily guess or brute-force administrative credentials "
                             "to gain elevated privileges.")
            impact = "Local system takeover leading to lateral movement across the network."
            imm_action = f"Immediately rotate the local administrator password on {hostname} ({ip}) and deploy LAPS."
        else:
            exploitation = "Adversaries could exploit this misconfiguration to execute unauthorized code or access sensitive data."
            impact = "Data breach or loss of system availability."
            imm_action = f"Investigate and patch/reconfigure {hostname} ({ip})."

        csa_name = ctx.get('csa_name')
        csa_impact_summary = (
            f"This finding threatens the ability to {csa_name.lower()}."
            if not _is_unresolved(csa_name) else
            "No DoD Cyber Survivability Attribute mapped to this technique in the graph."
        )

        mitre_name = ctx.get('technique_name', 'this technique')
        cref_approach = ctx.get('cref_approach')
        cref_goal = ctx.get('cref_goal')
        architectural_recommendation = (
            f"Because {mitre_name} can recur in forms tactical controls won't catch, "
            f"engineer for {str(cref_approach).lower()} ({str(cref_goal).lower()} the mission) "
            f"rather than relying solely on tactical blockers."
            if not _is_unresolved(cref_approach) else
            "No CREF architectural approach mapped to this technique in the graph; "
            "tactical controls are the primary mitigation for this finding."
        )

        zig_cap_name = ctx.get('zig_capability_name')
        cref_approach_resolved = not _is_unresolved(cref_approach)
        zig_cap_resolved = not _is_unresolved(zig_cap_name)
        long_term_action = (
            f"Integrate {zig_cap_name} architecture fully; adopt {cref_approach} per Section 4."
            if cref_approach_resolved and zig_cap_resolved else
            f"Integrate {zig_cap_name} architecture fully." if zig_cap_resolved else
            "Integrate a Zero Trust architecture capability fully."
        )

        return {
            "exploitation_scenario": exploitation,
            "business_impact": impact,
            "csa_impact_summary": csa_impact_summary,
            "architectural_recommendation": architectural_recommendation,
            "immediate_action": imm_action,
            "short_term_action": "Implement continuous monitoring for this vulnerability class.",
            "long_term_action": long_term_action,
        }

    def proofread(self, markdown_text: str) -> str:
        return markdown_text

    def qa_review(self, markdown_text: str, context: dict) -> dict:
        return {"verdict": "PASS", "notes": "Heuristic mode: no LLM QA performed; review manually."}


def get_provider(name=None) -> LLMProvider:
    """Factory that always returns a usable provider, degrading to the heuristic fallback on any error."""
    name = (name or os.environ.get('LLM_PROVIDER', 'none') or 'none').lower()

    if name == 'local':
        try:
            return LocalOpenAICompatProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=local but the 'openai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError as e:
            print(f"[Warning] LLM_PROVIDER=local but {e} Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    if name == 'openai':
        try:
            return OpenAIProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=openai but the 'openai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError:
            print("[Warning] LLM_PROVIDER=openai but OPENAI_API_KEY is not set. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    if name == 'gemini':
        try:
            return GeminiProvider()
        except ImportError:
            print("[Warning] LLM_PROVIDER=gemini but the 'google-generativeai' package is not installed. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()
        except ValueError:
            print("[Warning] LLM_PROVIDER=gemini but GEMINI_API_KEY is not set. Falling back to heuristic mode.")
            return HeuristicFallbackProvider()

    return HeuristicFallbackProvider()


if __name__ == "__main__":
    provider = get_provider()
    print(f"Using provider: {type(provider).__name__}")

    sample_context = {
        "technique_id": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets",
        "technique_description": "Adversaries may attempt to subvert Kerberos ticketing.",
        "tactic": "Credential Access",
        "affected_hosts": [
            {"ip": "10.0.0.12", "hostname": "DC01", "finding_text": "Unconstrained Kerberos Delegation enabled on DC01", "severity": "Critical"}
        ],
        "finding_count": 1,
        "severity_breakdown": {"Critical": 1},
        "d3fend_countermeasures": ["[D3-KAM] Kerberos Authentication Monitoring"],
        "d3fend_artifacts": [],
        "mitre_analytics": [],
        "mitre_mitigations": [],
        "zig_pillar": "Identity",
        "zig_capability_id": "ZIG-CAP-1.1",
        "zig_capability_name": "Authentication",
        "zig_activity_id": "ZIG-ACT-1.1.1",
        "zig_activity_name": "Enforce Kerberos Pre-Auth",
        "zig_technologies": [],
        "cref_goal": "Assure Mission",
        "cref_objective": "Prevent Escalation",
        "cref_technique": "Privilege Restriction",
        "cref_approach": "Least Privilege Enforcement",
        "cref_approach_id": "CREF-APP-3",
        "cref_effect": "Reduce Attack Surface",
        "cref_mitigation_id": "CREF-MIT-3",
        "cref_mitigation_name": "Delegation Hardening",
        "nist_controls": ["AC-6"],
        "csa_name": "Prevent Escalation of Privileges",
        "traceability": "Implements CREF Approach CREF-APP-3 / ZIG Activity ZIG-ACT-1.1.1",
    }

    result = provider.draft_narrative(sample_context)
    print(json.dumps(result, indent=2))
