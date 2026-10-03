"""Blast-Radius & State-Diff Impact Simulator for CloudSec-RAG v2.0.

Simulates infrastructure configuration state transitions and forecasts potential
service disruption or broken dependencies before executing automated patches.
"""

from typing import Any, Dict, List, Optional
from ..types import BlastRadius, BlastRadiusStateDiff, PatchAction


class BlastRadiusSimulator:
    """Predicts downstream microservice impacts and produces before/after configuration state-diffs."""

    def simulate_patch_impact(
        self,
        resource_id: str,
        patch: PatchAction,
        current_config: Optional[Dict[str, Any]] = None,
        known_dependencies: Optional[List[str]] = None,
    ) -> BlastRadiusStateDiff:
        """
        Simulate applying patch against current resource configuration.
        """
        deps = known_dependencies or []
        cmd = patch.command.lower()

        # Default configuration baseline
        before_state = current_config or {
            "resource_id": resource_id,
            "public_access": "ENABLED",
            "enforce_encryption": "DISABLED",
            "allowed_ingress_cidrs": ["0.0.0.0/0"],
        }
        after_state = dict(before_state)

        # 1. AWS S3 Public Access Block Simulation
        if "put-public-access-block" in cmd:
            after_state["public_access"] = "BLOCKED"
            after_state["block_public_policy"] = True
            after_state["restrict_public_buckets"] = True

            # If dependent services include public CDNs or unauthenticated external APIs
            disruptive = any("cdn" in d.lower() or "public-web" in d.lower() for d in deps)
            prob = 0.65 if disruptive else 0.05
            risk = BlastRadius.HIGH if disruptive else BlastRadius.MEDIUM

            summary = (
                f"Patch locks down bucket '{resource_id}'. Direct internet access is eliminated. "
                f"{len(deps)} dependent workloads inspected. Potential disruption: {prob * 100:.0f}%."
            )

        # 2. Ingress Rule Revocation Simulation (e.g. Port 22 / Port 3389)
        elif "revoke-security-group-ingress" in cmd or "nsg rule delete" in cmd:
            after_state["allowed_ingress_cidrs"] = ["10.0.0.0/16"]  # Corporate internal subnet
            prob = 0.10
            risk = BlastRadius.MEDIUM
            summary = (
                f"Port exposure revoked on '{resource_id}'. Untrusted internet ingress closed. "
                "Internal VPC routes remain operational."
            )

        # 3. Kubernetes SecurityContext Patch
        elif "patch deployment" in cmd:
            after_state["privileged"] = False
            after_state["readOnlyRootFilesystem"] = True
            prob = 0.15
            risk = BlastRadius.LOW
            summary = (
                f"Privileged flag stripped from container deployment '{resource_id}'. "
                "Workload restarts in hardened non-root sandbox."
            )

        # 4. IAM Role Detach / Least Privilege
        elif "detach-role-policy" in cmd:
            after_state["admin_access"] = False
            after_state["policy"] = "ReadOnlyAccess"
            prob = 0.25
            risk = BlastRadius.HIGH
            summary = (
                f"Administrator privileges stripped from role '{resource_id}'. "
                "Workload restricted to read-only capabilities."
            )

        else:
            prob = 0.05
            risk = BlastRadius.LOW
            summary = f"Patch applies configuration update to '{resource_id}' with minimal blast-radius."

        return BlastRadiusStateDiff(
            resource_id=resource_id,
            before_state=before_state,
            after_state=after_state,
            affected_dependent_services=deps,
            risk_level=risk,
            service_disruption_probability=prob,
            summary=summary,
        )
