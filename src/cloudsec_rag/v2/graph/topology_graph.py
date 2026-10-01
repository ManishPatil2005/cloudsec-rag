"""Multi-Cloud Asset & Identity Topology Graph for CloudSec-RAG v2.0.

Represents cloud infrastructure as a directed graph to discover attack vectors
and multi-hop relationships between compute, network, identity, and datastores.
"""

from collections import deque
from typing import Dict, List, Optional, Set
from ..types import CloudProvider, NodeType, RelationType, TopologyEdge, TopologyNode


class CloudTopologyGraph:
    """In-memory multi-cloud infrastructure graph."""

    def __init__(self):
        self.nodes: Dict[str, TopologyNode] = {}
        self.adjacency: Dict[str, List[TopologyEdge]] = {}
        self.reverse_adjacency: Dict[str, List[TopologyEdge]] = {}

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        provider: CloudProvider = CloudProvider.AWS,
        name: str = "",
        metadata: Optional[Dict] = None,
    ) -> TopologyNode:
        """Add or update an infrastructure node."""
        node = TopologyNode(
            node_id=node_id,
            node_type=node_type,
            provider=provider,
            name=name or node_id,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        if node_id not in self.adjacency:
            self.adjacency[node_id] = []
        if node_id not in self.reverse_adjacency:
            self.reverse_adjacency[node_id] = []
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: RelationType,
        metadata: Optional[Dict] = None,
    ) -> TopologyEdge:
        """Add a directed relationship between two nodes."""
        edge = TopologyEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            metadata=metadata or {},
        )
        if source_id not in self.adjacency:
            self.adjacency[source_id] = []
        if target_id not in self.reverse_adjacency:
            self.reverse_adjacency[target_id] = []

        self.adjacency[source_id].append(edge)
        self.reverse_adjacency[target_id].append(edge)
        return edge

    def find_paths_between(
        self, start_node_id: str, end_node_id: str, max_depth: int = 5
    ) -> List[List[str]]:
        """Find all directed paths between two nodes using Breadth-First Search (BFS)."""
        if start_node_id not in self.nodes or end_node_id not in self.nodes:
            return []

        paths = []
        queue = deque([(start_node_id, [start_node_id])])

        while queue:
            current, path = queue.popleft()
            if current == end_node_id and len(path) > 1:
                paths.append(path)
                continue

            if len(path) >= max_depth:
                continue

            for edge in self.adjacency.get(current, []):
                neighbor = edge.target_id
                if neighbor not in path:  # Prevent cyclic loops
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def get_internet_facing_nodes(self) -> List[TopologyNode]:
        """Retrieve all nodes directly connected to INTERNET or an INTERNET_GATEWAY."""
        results = []
        for node_id, node in self.nodes.items():
            for edge in self.reverse_adjacency.get(node_id, []):
                src_node = self.nodes.get(edge.source_id)
                if src_node and src_node.node_type in [NodeType.INTERNET, NodeType.INTERNET_GATEWAY]:
                    results.append(node)
                    break
        return results

    def get_connected_datastores(self, workload_id: str) -> List[TopologyNode]:
        """Find datastores accessible from a given compute workload."""
        datastores = []
        visited = set()
        queue = deque([workload_id])

        while queue:
            curr = queue.popleft()
            visited.add(curr)
            curr_node = self.nodes.get(curr)
            if curr_node and curr_node.node_type == NodeType.DATASTORE and curr != workload_id:
                datastores.append(curr_node)

            for edge in self.adjacency.get(curr, []):
                if edge.target_id not in visited:
                    queue.append(edge.target_id)

        return datastores
