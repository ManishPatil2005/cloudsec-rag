"""FastAPI REST API Routes for CloudSec-RAG v1 and v2."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ..core.exceptions import PromptInjectionAttemptError
from ..core.types import (
    BenchmarkReference,
    GroundedAnalysis,
    HITLDecision,
    CopilotMessageRequest,
    CopilotMessageResponse,
)
from ..copilot.copilot_service import CopilotSecurityService
from ..pipeline.orchestrator import CloudSecPipeline
from ..rag.knowledge_base import get_default_benchmarks
from ..v2.orchestrator_v2 import CloudSecPipelineV2
from ..v2.types import GroundedAnalysisV2, NetworkTopologyContext, PermissionContext

router = APIRouter(prefix="/api", tags=["Cloud Security Operations"])

pipeline_v1 = CloudSecPipeline()
pipeline_v2 = CloudSecPipelineV2()
copilot_service = CopilotSecurityService()


class AnalyzeRequest(BaseModel):
    raw_log: str = Field(..., description="Raw cloud log, alert text, JSON, or Kubernetes YAML")
    provider_hint: Optional[str] = Field(None, description="Optional provider hint (AWS, AZURE, GCP, KUBERNETES)")
    session_id: Optional[str] = Field(None, description="Working session identifier")


class AnalyzeRequestV2(BaseModel):
    raw_log: str = Field(..., description="Raw cloud log, alert text, JSON, or Kubernetes YAML")
    provider_hint: Optional[str] = Field(None, description="Optional provider hint (AWS, AZURE, GCP, KUBERNETES)")
    session_id: Optional[str] = Field(None, description="Working session identifier")
    is_public_subnet: bool = Field(True, description="Whether resource is in a public subnet with IGW route")
    scp_explicit_deny: bool = Field(False, description="Whether an AWS Org SCP blocks the operation")
    known_dependencies: List[str] = Field(default_factory=list, description="Downstream services for blast-radius check")


class HITLRequest(BaseModel):
    incident_id: str
    patch_id: str
    decision: str = Field(..., description="'APPROVED' or 'REJECTED'")
    operator_id: str = Field(..., description="Username or ID of operator")
    notes: Optional[str] = None


@router.get("/v1/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "CloudSec-RAG Orchestrator",
        "version": "2.0.0",
        "reachability_verifier": "active",
        "graph_rag_toxic_detector": "active",
        "sustainable_router": "active",
        "anti_hallucination": "active",
        "prompt_injection_shield": "active",
        "copilot_security_rules": "active",
        "memory_tier_2_sqlite": "connected",
    }


@router.post("/v1/analyze", response_model=GroundedAnalysis)
def analyze_cloud_log_v1(req: AnalyzeRequest):
    """Analyze a raw cloud alert with v1.0 grounded pipeline."""
    try:
        analysis = pipeline_v1.analyze_incident(
            raw_input=req.raw_log,
            session_id=req.session_id,
            provider_hint=req.provider_hint,
        )
        return analysis
    except PromptInjectionAttemptError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Adversarial Prompt Injection Detected",
                "pattern": e.pattern,
                "score": e.score,
                "status": "BLOCKED",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(e)}",
        )


@router.post("/v2/analyze", response_model=GroundedAnalysisV2)
def analyze_cloud_log_v2(req: AnalyzeRequestV2):
    """v2.0 Autonomous Analysis with reachability verification, toxic combination detection, and blast diff."""
    try:
        net_ctx = NetworkTopologyContext(
            vpc_id="vpc-prod",
            subnet_id="subnet-active",
            is_public_subnet=req.is_public_subnet,
            has_internet_gateway_route=req.is_public_subnet,
            ingress_cidrs=["0.0.0.0/0"] if req.is_public_subnet else ["10.0.0.0/16"],
        )

        perm_ctx = PermissionContext(
            has_resource_policy_allow=True,
            has_identity_policy_allow=True,
            scp_explicit_deny=req.scp_explicit_deny,
        )

        analysis_v2 = pipeline_v2.analyze_incident_v2(
            raw_input=req.raw_log,
            network_context=net_ctx,
            permission_context=perm_ctx,
            known_dependencies=req.known_dependencies,
            session_id=req.session_id,
            provider_hint=req.provider_hint,
        )
        return analysis_v2
    except PromptInjectionAttemptError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Adversarial Prompt Injection Detected",
                "pattern": e.pattern,
                "score": e.score,
                "status": "BLOCKED",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"v2 Analysis error: {str(e)}",
        )


@router.post("/v1/copilot/chat", response_model=CopilotMessageResponse)
def copilot_chat_endpoint(req: CopilotMessageRequest):
    """Secured AI Copilot endpoint with anti-injection shield, PII scrubbing, and problem reporting."""
    return copilot_service.handle_message(req)


@router.post("/v1/hitl/decision", response_model=HITLDecision)
def submit_hitl_decision(req: HITLRequest):
    """Submit human operator approval or rejection for a security patch."""
    decision = HITLDecision(
        decision_id=f"HITL-API-{req.incident_id[:8]}",
        incident_id=req.incident_id,
        patch_id=req.patch_id,
        decision=req.decision.upper(),
        operator_id=req.operator_id,
        notes=req.notes,
    )
    pipeline_v1.sqlite_store.save_hitl_decision(decision)
    return decision


@router.get("/v1/incidents", response_model=List[Dict[str, Any]])
def list_recent_incidents(limit: int = 25):
    """List recent cloud security incidents recorded in persistent SQLite memory."""
    return pipeline_v1.sqlite_store.get_recent_incidents(limit=limit)


@router.get("/v1/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """Retrieve full incident telemetry and grounded analysis."""
    incident = pipeline_v1.sqlite_store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    analysis = pipeline_v1.sqlite_store.get_analysis(incident_id)
    return {
        "incident": incident,
        "analysis": analysis,
    }


@router.get("/v1/benchmarks", response_model=List[BenchmarkReference])
def list_authoritative_benchmarks():
    """List all indexed CIS and NIST benchmarks available for grounding."""
    return get_default_benchmarks()


@router.get("/v1/sample-logs")
def get_sample_logs_catalog():
    """Retrieve master catalog of multi-cloud telemetry scenarios from sample_logs.json."""
    import json
    from pathlib import Path
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "data" / "sample_logs.json",
        Path("data/sample_logs.json"),
        Path("/var/task/data/sample_logs.json"),
    ]
    for sample_file in candidates:
        if sample_file.exists():
            with open(sample_file, "r", encoding="utf-8") as f:
                return json.load(f)
    return {"scenarios": []}


@router.get("/v1/security-rules")
def get_security_rules_doc():
    """Retrieve platform Security & Governance Rules."""
    from pathlib import Path
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "docs" / "SECURITY_RULES.md",
        Path("docs/SECURITY_RULES.md"),
        Path("/var/task/docs/SECURITY_RULES.md"),
    ]
    for rules_file in candidates:
        if rules_file.exists():
            with open(rules_file, "r", encoding="utf-8") as f:
                return {"content": f.read()}
    return {"content": "Security rules document not found."}
