"""Unit and integration tests for CloudSecPipelineV2."""

import os
import tempfile
from cloudsec_rag.core.types import Severity
from cloudsec_rag.v2.orchestrator_v2 import CloudSecPipelineV2
from cloudsec_rag.v2.types import NetworkTopologyContext, PermissionContext, SustainableTier


def test_v2_suppresses_false_positive_when_subnet_is_private():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        pipeline = CloudSecPipelineV2(db_path=db_path, llm_provider="mock")
        raw_alert = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-isolated-db region=ap-south-1 severity=HIGH"
        
        # Subnet is completely private (no IGW route)
        private_net = NetworkTopologyContext(
            vpc_id="vpc-corp-isolated",
            subnet_id="subnet-private-tier",
            is_public_subnet=False,
            has_internet_gateway_route=False,
        )

        analysis_v2 = pipeline.analyze_incident_v2(raw_alert, network_context=private_net)

        # Must be suppressed and downgraded
        assert analysis_v2.reachability.is_actually_vulnerable is False
        assert analysis_v2.severity == Severity.INFORMATIONAL
        assert "FALSE-POSITIVE ELIMINATED" in analysis_v2.plain_language_summary
        assert analysis_v2.executable_patch is None
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


def test_v2_confirms_reachable_and_computes_blast_diff():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        pipeline = CloudSecPipelineV2(db_path=db_path, llm_provider="mock")
        raw_alert = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH"
        
        # Public subnet with IGW
        public_net = NetworkTopologyContext(
            vpc_id="vpc-public",
            subnet_id="subnet-dmz",
            is_public_subnet=True,
            has_internet_gateway_route=True,
            ingress_cidrs=["0.0.0.0/0"],
        )

        analysis_v2 = pipeline.analyze_incident_v2(
            raw_alert,
            network_context=public_net,
            known_dependencies=["payment-frontend-web"],
        )

        assert analysis_v2.reachability.is_actually_vulnerable is True
        assert analysis_v2.executable_patch is not None
        assert analysis_v2.blast_radius_diff is not None
        assert "payment-frontend-web" in analysis_v2.blast_radius_diff.affected_dependent_services
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
