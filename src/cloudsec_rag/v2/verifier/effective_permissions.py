"""Effective Permission Evaluator for CloudSec-RAG v2.0.

Simulates authorization decisions by evaluating resource policies, identity policies,
permission boundaries, and organization Service Control Policies (SCPs).
"""

from typing import Optional
from ..types import PermissionContext, ReachabilityVerdict


class EffectivePermissionEvaluator:
    """Computes effective cloud IAM authorization state to detect policy override protections."""

    def evaluate_effective_access(
        self,
        resource_id: str,
        action: str,
        context: Optional[PermissionContext] = None,
    ) -> ReachabilityVerdict:
        """
        Evaluate if the cloud IAM control plane actually permits unauthorized access.
        """
        if not context:
            return ReachabilityVerdict(
                is_network_reachable=True,
                is_permission_effective=True,
                is_actually_vulnerable=True,
                verdict_summary="Permission context not provided; assuming effective permission.",
                confidence_score=0.70,
            )

        # 1. Check AWS Organizations Service Control Policy (SCP) Explicit Deny
        if context.scp_explicit_deny:
            return ReachabilityVerdict(
                is_network_reachable=True,
                is_permission_effective=False,
                is_actually_vulnerable=False,
                verdict_summary=(
                    f"Resource '{resource_id}' has a permissive policy, but the parent organization's "
                    "Service Control Policy (SCP) explicitly blocks this action."
                ),
                suppression_reason="SUPPRESSED: Organization-level SCP takes precedence and blocks execution.",
                confidence_score=0.99,
            )

        # 2. Check Permission Boundaries
        if not context.permission_boundary_allows:
            return ReachabilityVerdict(
                is_network_reachable=True,
                is_permission_effective=False,
                is_actually_vulnerable=False,
                verdict_summary=(
                    f"Action '{action}' exceeds the maximum allowed permissions defined by "
                    "the identity's Permission Boundary."
                ),
                suppression_reason="SUPPRESSED: Blocked by IAM Permission Boundary.",
                confidence_score=0.98,
            )

        # 3. Check Condition Key Guards (e.g. SourceIP or MFA Enforced)
        if context.source_ip_restricted or context.requires_mfa:
            guard_type = "MFA authentication" if context.requires_mfa else "internal corporate IP restriction"
            return ReachabilityVerdict(
                is_network_reachable=True,
                is_permission_effective=False,
                is_actually_vulnerable=False,
                verdict_summary=(
                    f"Resource '{resource_id}' policy contains an active Condition block requiring {guard_type}."
                ),
                suppression_reason=f"SUPPRESSED: Condition key requires {guard_type}.",
                confidence_score=0.96,
            )

        # If policy allows and no guard blocks it
        is_effective = context.has_resource_policy_allow or context.has_identity_policy_allow
        return ReachabilityVerdict(
            is_network_reachable=True,
            is_permission_effective=is_effective,
            is_actually_vulnerable=is_effective,
            verdict_summary=(
                f"CONFIRMED PERMISSION LEAK: Action '{action}' on '{resource_id}' is effectively permitted "
                "with no neutralizing SCP, boundary, or condition block."
            ),
            suppression_reason=None if is_effective else "SUPPRESSED: No effective policy grants access.",
            confidence_score=0.95,
        )
