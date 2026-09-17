"""Executable Multi-Cloud Security Patching Engine.

Generates validated CLI and Infrastructure-as-Code (IaC) patches across
AWS, Azure, GCP, and Kubernetes.
"""

from typing import List, Optional
from ..core.types import (
    BenchmarkReference,
    BlastRadius,
    CloudProvider,
    CloudSecurityIncident,
    PatchAction,
    PatchType,
)
from .validator import PatchValidator
from .rollback import RollbackGenerator


class SecurityPatchingEngine:
    """Produces multi-cloud remediation scripts and Terraform snippets with blast-radius analysis."""

    def __init__(
        self,
        validator: Optional[PatchValidator] = None,
        rollback_gen: Optional[RollbackGenerator] = None,
    ):
        self.validator = validator or PatchValidator()
        self.rollback_gen = rollback_gen or RollbackGenerator()

    def generate_patch(
        self, incident: CloudSecurityIncident, benchmark: Optional[BenchmarkReference] = None
    ) -> PatchAction:
        """Create a validated, actionable patch for an incident."""
        patch_id = f"PATCH-{incident.incident_id}"
        patch_type = self._resolve_patch_type(incident.provider)

        if benchmark:
            cmd = benchmark.remediation_command
            iac = benchmark.iac_template
            explanation = f"Grounded remediation derived from {benchmark.citation_id}: {benchmark.title}"
        else:
            cmd = f"# Review and isolate resource {incident.resource_id} on {incident.provider.value}"
            iac = f"# IaC lockdown template for {incident.resource_id}"
            explanation = f"General isolation patch for {incident.resource_id}"

        blast_radius = self.validator.estimate_blast_radius(cmd)

        patch = PatchAction(
            patch_id=patch_id,
            patch_type=patch_type,
            command=cmd,
            iac_code=iac,
            blast_radius=blast_radius,
            is_destructive=False,
            idempotent=True,
            dry_run_supported=True,
            explanation=explanation,
        )

        # Validate patch safety
        is_valid, reasons = self.validator.validate(patch)
        if not is_valid:
            # Degrade to safe comment mode if validation flagged issues
            patch.command = f"# SAFETY WARNING: Automated command was blocked:\n# {reasons[0]}\n# Manual verification required."

        return patch

    def _resolve_patch_type(self, provider: CloudProvider) -> PatchType:
        if provider == CloudProvider.AWS:
            return PatchType.AWS_CLI
        elif provider == CloudProvider.AZURE:
            return PatchType.AZURE_CLI
        elif provider == CloudProvider.GCP:
            return PatchType.GCLOUD
        elif provider == CloudProvider.KUBERNETES:
            return PatchType.KUBECTL
        return PatchType.AWS_CLI
