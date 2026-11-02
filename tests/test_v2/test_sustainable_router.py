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


def test_sustainable_router_lru_eviction():
    from cloudsec_rag.core.types import GroundedAnalysis
    router = SustainableInferenceRouter(max_cache_size=2)
    
    inc1 = CloudSecurityIncident(incident_id="I1", provider=CloudProvider.AWS, resource_id="r1", event_name="e1", raw_payload="p1", sanitized_payload="p1")
    inc2 = CloudSecurityIncident(incident_id="I2", provider=CloudProvider.AWS, resource_id="r2", event_name="e2", raw_payload="p2", sanitized_payload="p2")
    inc3 = CloudSecurityIncident(incident_id="I3", provider=CloudProvider.AWS, resource_id="r3", event_name="e3", raw_payload="p3", sanitized_payload="p3")

    analysis1 = GroundedAnalysis(incident_id="I1", resource_id="r1", provider=CloudProvider.AWS, risk_title="T1", severity=Severity.LOW, plain_language_summary="s", root_cause="r", technical_breakdown="t", grounding_confidence=0.95)
    analysis2 = GroundedAnalysis(incident_id="I2", resource_id="r2", provider=CloudProvider.AWS, risk_title="T2", severity=Severity.LOW, plain_language_summary="s", root_cause="r", technical_breakdown="t", grounding_confidence=0.95)
    analysis3 = GroundedAnalysis(incident_id="I3", resource_id="r3", provider=CloudProvider.AWS, risk_title="T3", severity=Severity.LOW, plain_language_summary="s", root_cause="r", technical_breakdown="t", grounding_confidence=0.95)

    router.cache_resolution(inc1, analysis1)
    router.cache_resolution(inc2, analysis2)
    assert len(router.signature_cache) == 2

    # Add 3rd item -> inc1 should be evicted (LRU)
    router.cache_resolution(inc3, analysis3)
    assert len(router.signature_cache) == 2
    
    tier1, cached1 = router.route_incident(inc1, [])
    assert tier1 != SustainableTier.TIER_0_CACHE  # inc1 was evicted!

    tier3, cached3 = router.route_incident(inc3, [])
    assert tier3 == SustainableTier.TIER_0_CACHE  # inc3 is present!
