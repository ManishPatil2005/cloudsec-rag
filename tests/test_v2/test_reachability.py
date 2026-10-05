"""Unit tests for NetworkReachabilityAnalyzer in v2.0."""

from cloudsec_rag.v2.types import NetworkTopologyContext
from cloudsec_rag.v2.verifier.reachability import NetworkReachabilityAnalyzer


def test_private_subnet_suppresses_false_positive():
    analyzer = NetworkReachabilityAnalyzer()
    private_ctx = NetworkTopologyContext(
        vpc_id="vpc-corp-isolated",
        subnet_id="subnet-db-private",
        is_public_subnet=False,
        has_internet_gateway_route=False,
        ingress_cidrs=["0.0.0.0/0"],  # Local SG rule might be loose, but subnet has no IGW
    )
    verdict = analyzer.evaluate_reachability("rds-postgres-prod", network_context=private_ctx)

    assert verdict.is_network_reachable is False
    assert verdict.is_actually_vulnerable is False
    assert "SUPPRESSED" in verdict.suppression_reason


def test_restricted_security_group_suppresses_false_positive():
    analyzer = NetworkReachabilityAnalyzer()
    corp_only_ctx = NetworkTopologyContext(
        vpc_id="vpc-app",
        subnet_id="subnet-app-01",
        is_public_subnet=True,
        has_internet_gateway_route=True,
        ingress_cidrs=["10.0.0.0/16"],  # Only internal corporate network
        allowed_ports=[80, 443],
    )
    verdict = analyzer.evaluate_reachability("internal-api", network_context=corp_only_ctx)

    assert verdict.is_network_reachable is False
    assert verdict.is_actually_vulnerable is False
    assert "blocks public internet access" in verdict.suppression_reason


def test_public_igw_confirmed_reachable():
    analyzer = NetworkReachabilityAnalyzer()
    public_ctx = NetworkTopologyContext(
        vpc_id="vpc-public",
        subnet_id="subnet-web-dmz",
        is_public_subnet=True,
        has_internet_gateway_route=True,
        ingress_cidrs=["0.0.0.0/0"],
        allowed_ports=[80, 443],
    )
    verdict = analyzer.evaluate_reachability("web-frontend-nginx", network_context=public_ctx)

    assert verdict.is_network_reachable is True
    assert verdict.is_actually_vulnerable is True
    assert verdict.suppression_reason is None
