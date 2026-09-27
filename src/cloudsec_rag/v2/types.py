"""Domain types and schemas for CloudSec-RAG v2.0.

Extends v1 with network reachability, effective permissions, topology graphs,
toxic combinations, blast-radius state-diffs, and sustainable routing tiers.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from ..core.types import (
    BenchmarkReference,
    BlastRadius,
    CloudProvider,
    GroundedAnalysis,
    IncidentStatus,
    PatchAction,
    RollbackAction,
    Severity,
)


class SustainableTier(str, Enum):
    TIER_0_CACHE = "TIER_0_CACHE"                # 0 tokens, instant hash/pattern hit (<1ms)
    TIER_1_LOCAL_SLM = "TIER_1_LOCAL_SLM"        # 0 external tokens, local embedding/BM25 (~5ms)
    TIER_2_DEEP_LLM = "TIER_2_DEEP_LLM"          # External LLM reasoning for novel/toxic combinations


class NodeType(str, Enum):
    INTERNET = "INTERNET"
    INTERNET_GATEWAY = "INTERNET_GATEWAY"
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    WORKLOAD = "WORKLOAD"      # EC2, K8s Pod, Lambda
    IAM_ROLE = "IAM_ROLE"
    DATASTORE = "DATASTORE"    # S3, RDS, Blob, BigQuery


class RelationType(str, Enum):
    ROUTES_TO = "ROUTES_TO"
    HOSTS = "HOSTS"
    ASSUMES = "ASSUMES"
    GRANTS_ACCESS = "GRANTS_ACCESS"
    ATTACHED_TO = "ATTACHED_TO"


class NetworkTopologyContext(BaseModel):
    """Network environmental context for reachability evaluation."""
    vpc_id: str = "vpc-default"
    subnet_id: str = "subnet-default"
    is_public_subnet: bool = False
    has_internet_gateway_route: bool = False
    ingress_cidrs: List[str] = Field(default_factory=list)  # e.g., ["0.0.0.0/0"]
    allowed_ports: List[int] = Field(default_factory=list)  # e.g., [80, 443, 22]


class PermissionContext(BaseModel):
    """IAM & organizational permission boundary context."""
    has_resource_policy_allow: bool = True
    has_identity_policy_allow: bool = True
    scp_explicit_deny: bool = False             # AWS Org Service Control Policy explicit deny
    permission_boundary_allows: bool = True
    requires_mfa: bool = False
    source_ip_restricted: bool = False


class ReachabilityVerdict(BaseModel):
    """Deterministic verdict on whether a detected vulnerability is actually exploitable."""
    is_network_reachable: bool = Field(description="Can packets reach this resource from the public internet?")
    is_permission_effective: bool = Field(description="Do effective IAM/SCP policies permit the action?")
    is_actually_vulnerable: bool = Field(description="True if both reachable/effective; False if blocked by controls")
    verdict_summary: str
    suppression_reason: Optional[str] = None
    confidence_score: float = 1.0


class TopologyNode(BaseModel):
    """Node in the multi-cloud infrastructure graph."""
    node_id: str
    node_type: NodeType
    provider: CloudProvider
    name: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """Directional relationship between cloud resources."""
    source_id: str
    target_id: str
    relation: RelationType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToxicCombination(BaseModel):
    """Multi-hop attack path chaining multiple vulnerabilities into a critical risk."""
    path_id: str
    entry_point_id: str
    target_asset_id: str
    chain: List[str] = Field(description="Ordered list of node IDs forming the attack vector")
    combined_severity: Severity = Severity.CRITICAL
    risk_narrative: str
    recommended_sever_edge: Optional[str] = Field(default=None, description="Optimal low-impact edge to break the chain")


class BlastRadiusStateDiff(BaseModel):
    """State-diff simulation predicting impact of a proposed security patch."""
    resource_id: str
    before_state: Dict[str, Any]
    after_state: Dict[str, Any]
    affected_dependent_services: List[str] = Field(default_factory=list)
    risk_level: BlastRadius = BlastRadius.LOW
    service_disruption_probability: float = 0.0
    summary: str


class GroundedAnalysisV2(GroundedAnalysis):
    """Enhanced analysis output for CloudSec-RAG v2.0."""
    reachability: ReachabilityVerdict
    toxic_combination: Optional[ToxicCombination] = None
    blast_radius_diff: Optional[BlastRadiusStateDiff] = None
    sustainable_tier_used: SustainableTier = SustainableTier.TIER_0_CACHE
    tokens_consumed: int = 0
    processing_latency_ms: float = 0.0
