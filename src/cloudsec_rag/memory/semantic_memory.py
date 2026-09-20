"""Tier 3: Long-Term Incident & Patch Semantic Graph.

Retains institutional knowledge of past remediations, confirmed false-positives,
and historical drift patterns to prevent amnesia across enterprise teams.
"""

from typing import Dict, List, Optional
from ..core.types import CloudSecurityIncident, GroundedAnalysis


class IncidentSemanticMemory:
    """Historical knowledge repository mapping incident signatures to past validated resolutions."""

    def __init__(self):
        # Maps signature (provider:event_name:resource_type) -> List of past resolutions
        self.patch_knowledge_graph: Dict[str, List[Dict]] = {}
        self.false_positive_suppressions: set = set()

    def record_resolution(self, incident: CloudSecurityIncident, analysis: GroundedAnalysis) -> None:
        """Store approved resolution in semantic memory."""
        sig = self._generate_signature(incident)
        if sig not in self.patch_knowledge_graph:
            self.patch_knowledge_graph[sig] = []

        entry = {
            "incident_id": incident.incident_id,
            "resource_id": incident.resource_id,
            "patch_command": analysis.executable_patch.command if analysis.executable_patch else "",
            "verified_at": analysis.analyzed_at.isoformat(),
            "confidence": analysis.grounding_confidence,
        }
        self.patch_knowledge_graph[sig].append(entry)

    def mark_false_positive(self, incident: CloudSecurityIncident, reason: str) -> None:
        """Remember a resource or event pattern marked as a false-positive by human operators."""
        sig = f"{incident.provider.value}:{incident.resource_id}:{incident.event_name}"
        self.false_positive_suppressions.add(sig)

    def is_known_false_positive(self, incident: CloudSecurityIncident) -> bool:
        """Check if an incident was previously marked as an approved exception/false-positive."""
        sig = f"{incident.provider.value}:{incident.resource_id}:{incident.event_name}"
        return sig in self.false_positive_suppressions

    def find_historical_remedies(self, incident: CloudSecurityIncident) -> List[Dict]:
        """Look up past patches executed for similar incidents."""
        sig = self._generate_signature(incident)
        return self.patch_knowledge_graph.get(sig, [])

    def _generate_signature(self, incident: CloudSecurityIncident) -> str:
        """Generate a semantic cluster key."""
        return f"{incident.provider.value}:{incident.event_name}"
