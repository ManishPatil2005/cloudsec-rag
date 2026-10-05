"""Unit tests for BlastRadiusSimulator."""

from cloudsec_rag.core.types import BlastRadius, PatchAction, PatchType
from cloudsec_rag.v2.simulation.blast_radius import BlastRadiusSimulator


def test_simulate_s3_patch_with_dependent_cdn():
    simulator = BlastRadiusSimulator()
    patch = PatchAction(
        patch_id="P-S3",
        patch_type=PatchType.AWS_CLI,
        command="aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true",
        explanation="Lockdown S3",
    )
    diff = simulator.simulate_patch_impact(
        resource_id="my-bucket",
        patch=patch,
        known_dependencies=["frontend-web-cdn", "static-assets-router"],
    )

    assert diff.before_state["public_access"] == "ENABLED"
    assert diff.after_state["public_access"] == "BLOCKED"
    assert diff.risk_level == BlastRadius.HIGH
    assert diff.service_disruption_probability > 0.50
