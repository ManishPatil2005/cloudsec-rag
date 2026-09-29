"""Network Reachability Analyzer for CloudSec-RAG v2.0.

Determines whether a misconfigured cloud asset is actually reachable
from the untrusted public internet, eliminating false positives.
"""

from typing import List, Optional
from ..types import NetworkTopologyContext, ReachabilityVerdict


class NetworkReachabilityAnalyzer:
    """Simulates network packet trajectories across VPCs, Route Tables, and Security Groups."""

    def evaluate_reachability(
        self,
        resource_id: str,
        network_context: Optional[NetworkTopologyContext] = None,
        target_port: Optional[int] = None,
    ) -> ReachabilityVerdict:
        """
        Evaluate if packets from public internet (0.0.0.0/0) can reach the resource.
        """
        if not network_context:
            # Default pessimistic baseline when topology metadata is omitted
            return ReachabilityVerdict(
                is_network_reachable=True,
                is_permission_effective=True,
                is_actually_vulnerable=True,
                verdict_summary="Topology metadata unavailable; assuming reachable as worst-case baseline.",
                confidence_score=0.75,
            )

        # 1. Check Internet Gateway & Public Subnet Route Table
        has_public_ingress_route = (
            network_context.is_public_subnet and network_context.has_internet_gateway_route
        )

        if not has_public_ingress_route:
            return ReachabilityVerdict(
                is_network_reachable=False,
                is_permission_effective=True,
                is_actually_vulnerable=False,
                verdict_summary=f"Resource '{resource_id}' is located in a private or air-gapped subnet without Internet Gateway route.",
                suppression_reason="SUPPRESSED: Inbound internet exposure is physically impossible due to private subnet isolation.",
                confidence_score=0.99,
            )

        # 2. Check Security Group / Ingress CIDR rules
        is_cidr_open = any(cidr in ["0.0.0.0/0", "::/0", "*"] for cidr in network_context.ingress_cidrs)
        
        # Check port exposure if specific port was requested
        is_port_open = True
        if target_port is not None and network_context.allowed_ports:
            is_port_open = (target_port in network_context.allowed_ports) or (0 in network_context.allowed_ports)

        if not is_cidr_open:
            return ReachabilityVerdict(
                is_network_reachable=False,
                is_permission_effective=True,
                is_actually_vulnerable=False,
                verdict_summary=f"Resource '{resource_id}' security groups restrict ingress to authorized internal CIDRs: {network_context.ingress_cidrs}.",
                suppression_reason="SUPPRESSED: Security group firewall blocks public internet access.",
                confidence_score=0.98,
            )

        if not is_port_open:
            return ReachabilityVerdict(
                is_network_reachable=False,
                is_permission_effective=True,
                is_actually_vulnerable=False,
                verdict_summary=f"Port {target_port} is not allowed by active security group ingress rules.",
                suppression_reason=f"SUPPRESSED: Port {target_port} is closed to incoming traffic.",
                confidence_score=0.98,
            )

        # Both route and security group permit public ingress
        return ReachabilityVerdict(
            is_network_reachable=True,
            is_permission_effective=True,
            is_actually_vulnerable=True,
            verdict_summary=f"CONFIRMED REACHABLE: Resource '{resource_id}' has a direct route to IGW and allows 0.0.0.0/0 ingress.",
            suppression_reason=None,
            confidence_score=0.97,
        )
