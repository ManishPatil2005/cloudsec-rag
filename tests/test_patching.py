"""Unit tests for patching engine, validator, and rollback generator."""

from cloudsec_rag.core.types import BlastRadius, PatchAction, PatchType
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
