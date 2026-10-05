"""Unit tests for EffectivePermissionEvaluator in v2.0."""

from cloudsec_rag.v2.types import PermissionContext
from cloudsec_rag.v2.verifier.effective_permissions import EffectivePermissionEvaluator


def test_scp_explicit_deny_suppresses_alert():
    evaluator = EffectivePermissionEvaluator()
    # Scenario: S3 Bucket has Public Read, BUT Organization SCP blocks public S3 access
    ctx = PermissionContext(
        has_resource_policy_allow=True,
        has_identity_policy_allow=True,
        scp_explicit_deny=True,  # Organization SCP denies action!
    )
    verdict = evaluator.evaluate_effective_access("bkt-customer-data", "s3:GetObject", context=ctx)

    assert verdict.is_permission_effective is False
    assert verdict.is_actually_vulnerable is False
    assert "SUPPRESSED" in verdict.suppression_reason
    assert "SCP" in verdict.suppression_reason


def test_mfa_condition_suppresses_alert():
    evaluator = EffectivePermissionEvaluator()
    ctx = PermissionContext(
        has_resource_policy_allow=True,
        has_identity_policy_allow=True,
        requires_mfa=True,  # Guarded by multi-factor authentication
    )
    verdict = evaluator.evaluate_effective_access("bkt-audit-logs", "s3:GetObject", context=ctx)

    assert verdict.is_permission_effective is False
    assert verdict.is_actually_vulnerable is False
    assert "MFA" in verdict.suppression_reason
