"""Grounded Hybrid RAG Retriever.

Orchestrates multi-cloud query formulation, metadata filtering, and citation verification.
"""

from typing import List, Optional
from ..core.types import BenchmarkReference, CloudProvider, CloudSecurityIncident
from .knowledge_base import get_default_benchmarks
from .vector_store import HybridVectorStore


class CloudSecRetriever:
    """Retrieves authoritative security benchmark controls grounded in cloud incidents."""

    def __init__(self, vector_store: Optional[HybridVectorStore] = None):
        self.vector_store = vector_store or HybridVectorStore()
        if not self.vector_store.documents:
            # Seed with default authoritative benchmarks
            self.vector_store.add_documents(get_default_benchmarks())

    def retrieve_grounded_controls(
        self, incident: CloudSecurityIncident, top_k: int = 3
    ) -> List[BenchmarkReference]:
        """Formulate incident query and retrieve top matching benchmark references."""
        # 1. Synthesize targeted query using provider, event name, and payload signals
        query_parts = [
            incident.provider.value,
            incident.event_name,
            incident.resource_id,
            incident.sanitized_payload[:500]  # Focus on key diagnostic indicators
        ]
        query = " ".join(query_parts)

        # 2. Execute hybrid search
        matches = self.vector_store.search_hybrid(query=query, top_k=top_k)

        # 3. Filter / prioritize provider alignment if available
        filtered_matches = []
        for match in matches:
            # Personalize remediation and rollback command templates with actual resource ID
            customized_ref = match.model_copy()
            customized_ref.remediation_command = customized_ref.remediation_command.replace(
                "{RESOURCE_ID}", incident.resource_id
            ).replace("{RESOURCE_GROUP}", incident.metadata.get("resourceGroup", "default-rg"))
            
            customized_ref.rollback_command = customized_ref.rollback_command.replace(
                "{RESOURCE_ID}", incident.resource_id
            ).replace("{RESOURCE_GROUP}", incident.metadata.get("resourceGroup", "default-rg"))

            if customized_ref.iac_template:
                customized_ref.iac_template = customized_ref.iac_template.replace(
                    "{RESOURCE_ID}", incident.resource_id
                ).replace("{RESOURCE_GROUP}", incident.metadata.get("resourceGroup", "default-rg"))

            filtered_matches.append(customized_ref)

        return filtered_matches
