"""Unit tests for SustainableInferenceRouter."""

from cloudsec_rag.core.types import BenchmarkReference, CloudProvider, CloudSecurityIncident, Severity
from cloudsec_rag.v2.router.sustainable_router import SustainableInferenceRouter
from cloudsec_rag.v2.types import SustainableTier, ToxicCombination


def test_sustainable_routing_tier_1_default():
    router = SustainableInferenceRouter()
    incident = CloudSecurityIncident(
        incident_id="INC-ROUTER-01",
        provider=CloudProvider.AWS,
        resource_id="bkt-simple",
        event_name="S3PublicBucket",
        raw_payload="test",
        sanitized_payload="test",
    )
    bench = BenchmarkReference(
        citation_id="CIS-AWS-2.1.5",
        framework="CIS",
        title="S3 Public Access",
        description="Block access",
        rationale="Safety",
        impact="High",
        remediation_command="aws s3api ...",
        rollback_command="aws s3api ...",
        similarity_score=0.95,
    )

    tier, cached = router.route_incident(incident, [bench], toxic_combo=None)
    assert tier == SustainableTier.TIER_1_LOCAL_SLM
    assert cached is None
    assert router.stats["tier_1_hits"] == 1


def test_sustainable_routing_tier_2_for_toxic_combo():
    router = SustainableInferenceRouter()
    incident = CloudSecurityIncident(
        incident_id="INC-ROUTER-02",
        provider=CloudProvider.AWS,
        resource_id="bkt-pii",
        event_name="S3PublicBucket",
        raw_payload="test",
        sanitized_payload="test",
    )
    toxic = ToxicCombination(
        path_id="TX-01",
        entry_point_id="internet",
        target_asset_id="bkt-pii",
        chain=["internet", "ec2", "bkt-pii"],
        risk_narrative="Toxic multi-hop chain",
    )

    tier, _ = router.route_incident(incident, [], toxic_combo=toxic)
    assert tier == SustainableTier.TIER_2_DEEP_LLM
    assert router.stats["tier_2_hits"] == 1
