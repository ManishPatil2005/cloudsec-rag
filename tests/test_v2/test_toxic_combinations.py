"""Unit tests for Topology Graph and Toxic Combination Detector."""

from cloudsec_rag.v2.graph.topology_graph import CloudTopologyGraph
from cloudsec_rag.v2.graph.toxic_combinations import ToxicCombinationDetector
from cloudsec_rag.v2.types import NodeType, RelationType, Severity


def test_detect_toxic_attack_path():
    graph = CloudTopologyGraph()

    # Build multi-hop attack chain: Internet -> IGW -> EC2 -> IAM Role -> S3 Bucket
    graph.add_node("internet", NodeType.INTERNET, name="Internet")
    graph.add_node("igw-01", NodeType.INTERNET_GATEWAY, name="Prod IGW")
    graph.add_node("ec2-web", NodeType.WORKLOAD, name="Web Pod")
    graph.add_node("iam-admin-role", NodeType.IAM_ROLE, name="Admin Role")
    graph.add_node("bkt-pii-data", NodeType.DATASTORE, name="Customer PII S3")

    graph.add_edge("internet", "igw-01", RelationType.ROUTES_TO)
    graph.add_edge("igw-01", "ec2-web", RelationType.ROUTES_TO)
    graph.add_edge("ec2-web", "iam-admin-role", RelationType.ASSUMES)
    graph.add_edge("iam-admin-role", "bkt-pii-data", RelationType.GRANTS_ACCESS)

    detector = ToxicCombinationDetector(graph)
    toxic_paths = detector.discover_toxic_attack_paths()

    assert len(toxic_paths) >= 1
    top_toxic = toxic_paths[0]
    assert top_toxic.combined_severity == Severity.CRITICAL
    assert top_toxic.entry_point_id == "internet"
    assert top_toxic.target_asset_id == "bkt-pii-data"
    assert "CRITICAL TOXIC COMBINATION" in top_toxic.risk_narrative
