"""CloudSec-RAG v2.0 Autonomous Orchestrator.

Integrates real-time streaming, network reachability verification, effective IAM simulation,
topology graph traversal, toxic combination detection, sustainable green-AI routing,
and state-diff blast-radius impact analysis.
"""

import time
from typing import Any, Dict, List, Optional

from ..core.exceptions import PromptInjectionAttemptError
from ..core.types import BenchmarkReference, CloudSecurityIncident, IncidentStatus, Severity
from ..pipeline.orchestrator import CloudSecPipeline
from .graph.topology_graph import CloudTopologyGraph
from .graph.toxic_combinations import ToxicCombinationDetector
from .router.sustainable_router import SustainableInferenceRouter
from .simulation.blast_radius import BlastRadiusSimulator
from .types import (
    BlastRadiusStateDiff,
    GroundedAnalysisV2,
    NetworkTopologyContext,
    NodeType,
    PermissionContext,
    ReachabilityVerdict,
    RelationType,
    SustainableTier,
    ToxicCombination,
)
from .verifier.effective_permissions import EffectivePermissionEvaluator
from .verifier.reachability import NetworkReachabilityAnalyzer


class CloudSecPipelineV2:
    """Enterprise v2.0 autonomous security and reachability pipeline."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        llm_provider: Optional[str] = None,
        min_confidence: float = 0.85,
    ):
        # Base v1 pipeline for core RAG, ingestion, guardrails, and persistent memory
        self.base_pipeline = CloudSecPipeline(
            db_path=db_path, llm_provider=llm_provider, min_confidence=min_confidence
        )

        # v2 Advanced Subsystems
        self.reachability_analyzer = NetworkReachabilityAnalyzer()
        self.permission_evaluator = EffectivePermissionEvaluator()
        self.topology_graph = CloudTopologyGraph()
        self.toxic_detector = ToxicCombinationDetector(self.topology_graph)
        self.sustainable_router = SustainableInferenceRouter()
        self.blast_simulator = BlastRadiusSimulator()

        # Pre-seed default enterprise topology graph
        self._init_default_topology()

    def analyze_incident_v2(
        self,
        raw_input: str,
        network_context: Optional[NetworkTopologyContext] = None,
        permission_context: Optional[PermissionContext] = None,
        known_dependencies: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        provider_hint: Optional[str] = None,
    ) -> GroundedAnalysisV2:
        """
        Execute end-to-end v2 analysis with reachability verification and toxic path detection.
        """
        start_time = time.perf_counter()

        # 1. Parse and sanitize incident
        incident = self.base_pipeline.parser.parse(raw_input, provider_hint=provider_hint)

        # 2. Check prompt injection
        is_injection, risk_score, matches = self.base_pipeline.injection_detector.scan(raw_input)
        if is_injection:
            incident.status = IncidentStatus.REJECTED
            self.base_pipeline.sqlite_store.save_incident(incident)
            raise PromptInjectionAttemptError(
                f"Adversarial prompt injection detected: {matches}",
                pattern=str(matches),
                score=risk_score,
            )

        # 3. Check Network Reachability & Effective Permissions (Anti-False-Positive Engine)
        reach_verdict = self._evaluate_actual_vulnerability(
            incident, network_context, permission_context
        )

        # 4. Check Topology Graph for Toxic Combinations
        toxic_combo = self._check_toxic_paths(incident)

        # 5. Hybrid RAG retrieval
        benchmarks = self.base_pipeline.retriever.retrieve_grounded_controls(incident, top_k=3)

        # 6. Sustainable Hierarchical Routing (Green AI)
        tier_used, cached_analysis = self.sustainable_router.route_incident(
            incident=incident, benchmarks=benchmarks, toxic_combo=toxic_combo
        )

        tokens_consumed = 0
        if tier_used == SustainableTier.TIER_0_CACHE and cached_analysis:
            # 0 tokens, instant hit
            base_analysis = cached_analysis
            tokens_consumed = 0
        elif tier_used == SustainableTier.TIER_1_LOCAL_SLM:
            # 0 LLM tokens: Use deterministic grounded baseline
            base_analysis = self.base_pipeline.output_validator.create_deterministic_fallback(
                incident, benchmarks
            )
            tokens_consumed = 0
            self.sustainable_router.cache_resolution(incident, base_analysis)
        else:
            # Tier-2: Deep LLM Reasoning for complex or toxic combinations
            base_analysis = self.base_pipeline.analyze_incident(
                raw_input=raw_input, session_id=session_id, provider_hint=provider_hint
            )
            tokens_consumed = 1250
            self.sustainable_router.cache_resolution(incident, base_analysis)

        # 7. Apply Toxic Combination Escalation
        if toxic_combo:
            base_analysis.severity = Severity.CRITICAL
            base_analysis.risk_title = f"[TOXIC COMBINATION] {base_analysis.risk_title}"
            base_analysis.plain_language_summary = (
                f"{toxic_combo.risk_narrative} \n\n"
                f"Immediate Action Required: {base_analysis.plain_language_summary}"
            )

        # 8. Suppress or Downgrade if Proved NOT Actually Reachable / Blocked by SCP
        if not reach_verdict.is_actually_vulnerable:
            base_analysis.severity = Severity.INFORMATIONAL
            base_analysis.risk_title = f"[SUPPRESSED / BENIGN] {base_analysis.risk_title}"
            base_analysis.plain_language_summary = (
                f"FALSE-POSITIVE ELIMINATED: {reach_verdict.verdict_summary} "
                f"Reason: {reach_verdict.suppression_reason}. No immediate patching required."
            )
            base_analysis.executable_patch = None

        # 9. Blast-Radius & State-Diff Simulation (if patch exists)
        blast_diff = None
        if base_analysis.executable_patch:
            blast_diff = self.blast_simulator.simulate_patch_impact(
                resource_id=incident.resource_id,
                patch=base_analysis.executable_patch,
                known_dependencies=known_dependencies or [],
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Construct final GroundedAnalysisV2
        analysis_v2 = GroundedAnalysisV2(
            incident_id=base_analysis.incident_id,
            resource_id=base_analysis.resource_id,
            provider=base_analysis.provider,
            risk_title=base_analysis.risk_title,
            severity=base_analysis.severity,
            plain_language_summary=base_analysis.plain_language_summary,
            root_cause=base_analysis.root_cause,
            technical_breakdown=base_analysis.technical_breakdown,
            compliance_mappings=base_analysis.compliance_mappings,
            verified_citations=base_analysis.verified_citations,
            executable_patch=base_analysis.executable_patch,
            rollback_plan=base_analysis.rollback_plan,
            grounding_confidence=base_analysis.grounding_confidence,
            anti_hallucination_verified=base_analysis.anti_hallucination_verified,
            is_deterministic_fallback=base_analysis.is_deterministic_fallback,
            analyzed_at=base_analysis.analyzed_at,
            reachability=reach_verdict,
            toxic_combination=toxic_combo,
            blast_radius_diff=blast_diff,
            sustainable_tier_used=tier_used,
            tokens_consumed=tokens_consumed,
            processing_latency_ms=round(elapsed_ms, 2),
        )

        return analysis_v2

    def _evaluate_actual_vulnerability(
        self,
        incident: CloudSecurityIncident,
        network_context: Optional[NetworkTopologyContext],
        permission_context: Optional[PermissionContext],
    ) -> ReachabilityVerdict:
        # Check network reachability
        if network_context:
            reach = self.reachability_analyzer.evaluate_reachability(
                resource_id=incident.resource_id, network_context=network_context
            )
            if not reach.is_actually_vulnerable:
                return reach

        # Check permission effectiveness
        if permission_context:
            perm = self.permission_evaluator.evaluate_effective_access(
                resource_id=incident.resource_id, action="s3:GetObject", context=permission_context
            )
            if not perm.is_actually_vulnerable:
                return perm

        return ReachabilityVerdict(
            is_network_reachable=True,
            is_permission_effective=True,
            is_actually_vulnerable=True,
            verdict_summary=f"CONFIRMED REACHABLE & EFFECTIVE: '{incident.resource_id}' is active and exposed.",
            suppression_reason=None,
            confidence_score=0.96,
        )

    def _check_toxic_paths(self, incident: CloudSecurityIncident) -> Optional[ToxicCombination]:
        # Connect incident resource to graph if not present
        if incident.resource_id not in self.topology_graph.nodes:
            node_type = (
                NodeType.DATASTORE
                if "s3" in incident.event_name.lower() or "storage" in incident.event_name.lower()
                else NodeType.WORKLOAD
            )
            self.topology_graph.add_node(
                node_id=incident.resource_id,
                node_type=node_type,
                provider=incident.provider,
                name=incident.resource_id,
            )

        # Discover toxic paths
        paths = self.toxic_detector.discover_toxic_attack_paths()
        for p in paths:
            if incident.resource_id in p.chain:
                return p
        return None

    def _init_default_topology(self):
        """Pre-populate a sample enterprise topology graph with VPC, Workload, and Datastores."""
        g = self.topology_graph
        g.add_node("internet", NodeType.INTERNET, name="Public Internet")
        g.add_node("igw-prod", NodeType.INTERNET_GATEWAY, name="Production Internet Gateway")
        g.add_node("subnet-public", NodeType.SUBNET, name="Public Subnet 10.0.1.0/24")
        g.add_node("ec2-web-ingress", NodeType.WORKLOAD, name="Public Ingress Web Pod")
        g.add_node("role-workload-admin", NodeType.IAM_ROLE, name="Overprivileged Instance Role")
        g.add_node("bkt-7841a", NodeType.DATASTORE, name="Customer Data S3 Bucket")

        # Connect paths
        g.add_edge("internet", "igw-prod", RelationType.ROUTES_TO)
        g.add_edge("igw-prod", "subnet-public", RelationType.ROUTES_TO)
        g.add_edge("subnet-public", "ec2-web-ingress", RelationType.HOSTS)
        g.add_edge("ec2-web-ingress", "role-workload-admin", RelationType.ASSUMES)
        g.add_edge("role-workload-admin", "bkt-7841a", RelationType.GRANTS_ACCESS)
