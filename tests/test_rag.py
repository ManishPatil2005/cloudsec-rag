"""Unit tests for RAG knowledge base and hybrid retrieval."""

from cloudsec_rag.core.types import CloudProvider, CloudSecurityIncident
from cloudsec_rag.rag.retriever import CloudSecRetriever
from cloudsec_rag.rag.vector_store import HybridVectorStore


def test_hybrid_vector_store_retrieves_cis_control():
    retriever = CloudSecRetriever()
    
    incident = CloudSecurityIncident(
        incident_id="INC-TEST01",
        provider=CloudProvider.AWS,
        resource_id="bkt-customer-vault",
        event_name="S3BucketPolicyPublicRead",
        raw_payload="Bucket policy contains Effect: Allow, Principal: *, Action: s3:GetObject",
        sanitized_payload="Bucket policy contains Effect: Allow, Principal: *, Action: s3:GetObject"
    )

    matches = retriever.retrieve_grounded_controls(incident, top_k=2)
    assert len(matches) > 0
    # Top match should be CIS-AWS-2.1.5 or related storage control
    top = matches[0]
    assert "CIS-AWS-2.1.5" in top.citation_id or "S3" in top.title
    # Check resource customization
    assert "bkt-customer-vault" in top.remediation_command
    assert "bkt-customer-vault" in top.rollback_command
