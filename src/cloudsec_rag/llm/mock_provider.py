"""Deterministic Mock LLM Provider for Offline CI/CD and Local Execution.

Simulates advanced LLM reasoning strictly grounded in retrieved benchmarks.
Guarantees zero external network dependencies and immediate execution.
"""

import json
from typing import List
from ..core.types import BenchmarkReference, CloudSecurityIncident, MemoryItem
from .base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    """Generates grounded JSON responses mimicking high-end LLM output."""

    def generate_security_analysis(
        self,
        incident: CloudSecurityIncident,
        benchmarks: List[BenchmarkReference],
        conversation_context: List[MemoryItem],
        canary_token: str,
    ) -> str:
        """Produce structured, citation-grounded response."""
        top_ref = benchmarks[0] if benchmarks else None
        citation_id = top_ref.citation_id if top_ref else "CIS-GENERAL-1.0"
        framework = top_ref.framework if top_ref else "CIS_BENCHMARKS"
        title = top_ref.title if top_ref else "Cloud Misconfiguration Detected"
        cmd = top_ref.remediation_command if top_ref else f"# Remediate {incident.resource_id}"
        rb_cmd = top_ref.rollback_command if top_ref else f"# Rollback {incident.resource_id}"
        iac = top_ref.iac_template if top_ref else None

        # Build plain language explanation matching presentation PDF guidance:
        # "Clear risk, clear cause, clear fix — understandable by anyone, expert or not."
        plain_lang = (
            f"Your cloud resource '{incident.resource_id}' ({incident.provider.value}) has a critical vulnerability: "
            f"{top_ref.description if top_ref else 'Permissive access or insecure settings'}. "
            f"This is high risk -- anyone or any compromised asset could exploit it. "
            f"Fix it immediately by restricting the settings using the provided patch."
        )

        response_dict = {
            "risk_title": f"[{citation_id}] {title}",
            "severity": incident.severity_hint.value,
            "plain_language_summary": plain_lang,
            "root_cause": (
                f"Resource '{incident.resource_id}' violates security control {citation_id} ({framework}). "
                f"Triggered by event '{incident.event_name}'."
            ),
            "technical_breakdown": (
                f"Detailed inspection of telemetry for {incident.resource_id} indicates non-compliance with {framework}. "
                f"Impact: {top_ref.impact if top_ref else 'Exposure to unauthorized access.'}"
            ),
            "compliance_mappings": [citation_id, framework, "NIST_SP_800_53_AC_3"],
            "grounding_confidence": 0.96,
            "executable_patch": {
                "patch_id": f"PATCH-{incident.incident_id}",
                "patch_type": "AWS_CLI" if incident.provider.value == "AWS" else "KUBECTL" if incident.provider.value == "KUBERNETES" else "AZURE_CLI" if incident.provider.value == "AZURE" else "GCLOUD",
                "command": cmd,
                "iac_code": iac,
                "blast_radius": "HIGH" if "put-public-access-block" in cmd else "MEDIUM",
                "is_destructive": False,
                "idempotent": True,
                "explanation": f"Enforces {citation_id} compliance."
            },
            "rollback_plan": {
                "rollback_id": f"RB-{incident.incident_id}",
                "command": rb_cmd,
                "safety_instructions": "Execute only if business connectivity is interrupted."
            }
        }

        return json.dumps(response_dict, indent=2)
