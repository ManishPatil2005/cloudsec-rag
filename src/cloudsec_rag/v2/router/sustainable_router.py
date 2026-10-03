"""Sustainable Green-AI Hierarchical Inference Router for CloudSec-RAG v2.0.

Minimizes token consumption, carbon footprint, and operational costs by routing
cloud security incidents through a tiered compute hierarchy:
- Tier-0: Microsecond Signature & Hash Cache (0 Tokens, <1ms)
- Tier-1: Local Subword Embedder & BM25 Vector Match (0 External Tokens, ~5ms)
- Tier-2: Deep Grounded LLM Reasoner (Only for Novel/Toxic Multi-Hop Combinations)
"""

import hashlib
import time
from typing import Dict, List, Optional, Tuple
from ...core.types import BenchmarkReference, CloudSecurityIncident, GroundedAnalysis
from ..types import SustainableTier, ToxicCombination


class SustainableInferenceRouter:
    """Intelligent green router directing security events to the lowest-energy sufficient compute tier."""

    def __init__(self, token_cost_per_1k: float = 0.002):
        self.token_cost_per_1k = token_cost_per_1k
        # Tier-0 Hash Cache: maps payload hash -> cached GroundedAnalysis
        self.signature_cache: Dict[str, GroundedAnalysis] = {}
        self.stats = {
            "tier_0_hits": 0,
            "tier_1_hits": 0,
            "tier_2_hits": 0,
            "total_tokens_saved": 0,
            "cost_saved_usd": 0.0,
        }

    def route_incident(
        self,
        incident: CloudSecurityIncident,
        benchmarks: List[BenchmarkReference],
        toxic_combo: Optional[ToxicCombination] = None,
    ) -> Tuple[SustainableTier, Optional[GroundedAnalysis]]:
        """
        Determine appropriate inference tier.
        
        Returns:
            Tuple of (SustainableTier, Optional[CachedGroundedAnalysis])
        """
        # 1. Tier-0 Check: Exact Hash / Known Signature Cache
        sig_key = self._compute_incident_hash(incident)
        if sig_key in self.signature_cache:
            self.stats["tier_0_hits"] += 1
            self.stats["total_tokens_saved"] += 1200  # Avg tokens saved per triage call
            self.stats["cost_saved_usd"] += (1200 / 1000) * self.token_cost_per_1k
            return SustainableTier.TIER_0_CACHE, self.signature_cache[sig_key]

        # 2. Check Complexity: Does it require Tier-2 Deep LLM Reasoning?
        # Requires deep reasoning if:
        # - Toxic combination was discovered (multi-hop attack vector)
        # - Benchmark similarity is low or ambiguous (< 0.70)
        has_toxic = toxic_combo is not None
        top_bench_similarity = benchmarks[0].similarity_score if benchmarks and benchmarks[0].similarity_score else 0.0
        is_ambiguous = top_bench_similarity < 0.70

        if has_toxic or is_ambiguous:
            # Route to Tier-2
            self.stats["tier_2_hits"] += 1
            return SustainableTier.TIER_2_DEEP_LLM, None

        # 3. Default to Tier-1: Local Fast Embedding & CIS Benchmark Match (0 external tokens)
        self.stats["tier_1_hits"] += 1
        self.stats["total_tokens_saved"] += 1000
        self.stats["cost_saved_usd"] += (1000 / 1000) * self.token_cost_per_1k
        return SustainableTier.TIER_1_LOCAL_SLM, None

    def cache_resolution(self, incident: CloudSecurityIncident, analysis: GroundedAnalysis) -> None:
        """Cache verified resolution in Tier-0 cache for future 0-token instant lookups."""
        sig_key = self._compute_incident_hash(incident)
        self.signature_cache[sig_key] = analysis

    def _compute_incident_hash(self, incident: CloudSecurityIncident) -> str:
        """Create deterministic key from provider, event, and core sanitized payload."""
        content = f"{incident.provider.value}:{incident.event_name}:{incident.sanitized_payload}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
