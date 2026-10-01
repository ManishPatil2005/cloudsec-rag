"""Toxic Combination Detector for CloudSec-RAG v2.0.

Discovers chained multi-hop attack vectors where minor/moderate misconfigurations
aggregate into a Critical enterprise security breach.
"""

import uuid
from typing import List, Optional
from ..types import NodeType, Severity, ToxicCombination
from .topology_graph import CloudTopologyGraph


class ToxicCombinationDetector:
    """Analyzes topology paths to uncover full-chain compromise pathways."""

    def __init__(self, graph: CloudTopologyGraph):
        self.graph = graph

    def discover_toxic_attack_paths(self) -> List[ToxicCombination]:
        """
        Traverse graph from Internet/Gateway nodes to sensitive Datastores
        to find unmitigated multi-hop exfiltration vectors.
        """
        toxic_paths: List[ToxicCombination] = []

        # 1. Identify all external entry points (Internet or Internet Gateways)
        entry_points = [
            node for node in self.graph.nodes.values()
            if node.node_type in [NodeType.INTERNET, NodeType.INTERNET_GATEWAY]
        ]

        # 2. Identify all sensitive Datastore targets
        target_datastores = [
            node for node in self.graph.nodes.values()
            if node.node_type == NodeType.DATASTORE
        ]

        for entry in entry_points:
            for target in target_datastores:
                paths = self.graph.find_paths_between(entry.node_id, target.node_id, max_depth=6)
                for path in paths:
                    # Analyze chain composition
                    has_workload = any(
                        self.graph.nodes[nid].node_type == NodeType.WORKLOAD for nid in path
                    )
                    has_iam_role = any(
                        self.graph.nodes[nid].node_type == NodeType.IAM_ROLE for nid in path
                    )

                    # A toxic combination exists when an internet-facing workload has an assumed IAM identity that grants access to a datastore
                    if has_workload and has_iam_role:
                        chain_desc = " -> ".join([self.graph.nodes[nid].name for nid in path])
                        
                        # Find best severing node: usually the IAM Role or Security Group
                        sever_node = None
                        for nid in path:
                            if self.graph.nodes[nid].node_type in [NodeType.IAM_ROLE, NodeType.SECURITY_GROUP]:
                                sever_node = nid
                                break

                        toxic_combo = ToxicCombination(
                            path_id=f"TOXIC-{uuid.uuid4().hex[:6].upper()}",
                            entry_point_id=entry.node_id,
                            target_asset_id=target.node_id,
                            chain=path,
                            combined_severity=Severity.CRITICAL,
                            risk_narrative=(
                                f"CRITICAL TOXIC COMBINATION DETECTED: Untrusted internet traffic entering via '{entry.name}' "
                                f"can pivot through workload to assume IAM permissions and directly access datastore '{target.name}'. "
                                f"Chain: {chain_desc}"
                            ),
                            recommended_sever_edge=sever_node,
                        )
                        toxic_paths.append(toxic_combo)

        return toxic_paths
