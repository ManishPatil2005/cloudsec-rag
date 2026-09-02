"""Core domain models and schema definitions for CloudSec-RAG."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    KUBERNETES = "KUBERNETES"
    MULTI_CLOUD = "MULTI_CLOUD"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    SANITIZED = "SANITIZED"
    ANALYZED = "ANALYZED"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    APPROVED = "APPROVED"
    REMEDIATED = "REMEDIATED"
    ROLLBACK_EXECUTED = "ROLLBACK_EXECUTED"
    REJECTED = "REJECTED"


class PatchType(str, Enum):
    AWS_CLI = "AWS_CLI"
    AZURE_CLI = "AZURE_CLI"
    GCLOUD = "GCLOUD"
    KUBECTL = "KUBECTL"
    TERRAFORM = "TERRAFORM"
    K8S_MANIFEST = "K8S_MANIFEST"


class BlastRadius(str, Enum):
    LOW = "LOW"         # Minimal impact, e.g. adding tags or enabling logging
    MEDIUM = "MEDIUM"   # Moderate impact, e.g. restricting IAM policy on single user
    HIGH = "HIGH"       # Severe impact, e.g. updating network security group or S3 public access block


class BenchmarkReference(BaseModel):
    """Authoritative benchmark entry (CIS, NIST, MITRE)."""
    citation_id: str = Field(description="Unique standard ID, e.g., 'CIS-AWS-2.1.5' or 'NIST-AC-3'")
    framework: str = Field(description="Framework name, e.g., CIS, NIST_SP_800_53, MITRE_ATTACK")
    title: str
    description: str
    rationale: str
    impact: str
    remediation_command: str
    rollback_command: str
    iac_template: Optional[str] = None
    similarity_score: Optional[float] = None


class CloudSecurityIncident(BaseModel):
    """Raw and structured representation of an ingested cloud security event."""
    incident_id: str
    provider: CloudProvider
    resource_id: str
    event_name: str
    region: Optional[str] = "global"
    severity_hint: Severity = Severity.MEDIUM
    raw_payload: str
    sanitized_payload: str = ""
    secrets_redacted_count: int = 0
    injection_risk_score: float = 0.0
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    status: IncidentStatus = IncidentStatus.DETECTED
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PatchAction(BaseModel):
    """Validated patch to execute."""
    patch_id: str
    patch_type: PatchType
    command: str
    iac_code: Optional[str] = None
    blast_radius: BlastRadius = BlastRadius.LOW
    is_destructive: bool = False
    idempotent: bool = True
    dry_run_supported: bool = True
    explanation: str


class RollbackAction(BaseModel):
    """Automated inverse rollback plan."""
    rollback_id: str
    target_patch_id: str
    command: str
    iac_revert_code: Optional[str] = None
    safety_instructions: str


class GroundedAnalysis(BaseModel):
    """Verified, hallucination-free security analysis."""
    incident_id: str
    resource_id: str
    provider: CloudProvider
    risk_title: str
    severity: Severity
    plain_language_summary: str = Field(description="Clear explanation understandable by non-security staff")
    root_cause: str
    technical_breakdown: str
    compliance_mappings: List[str] = Field(default_factory=list)
    verified_citations: List[BenchmarkReference] = Field(default_factory=list)
    executable_patch: Optional[PatchAction] = None
    rollback_plan: Optional[RollbackAction] = None
    grounding_confidence: float = Field(ge=0.0, le=1.0)
    anti_hallucination_verified: bool = True
    is_deterministic_fallback: bool = False
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class HITLDecision(BaseModel):
    """Human-in-the-Loop approval decision."""
    decision_id: str
    incident_id: str
    patch_id: str
    decision: str  # "APPROVED" or "REJECTED"
    operator_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None


class MemoryItem(BaseModel):
    """Entry in 3-Tier memory system."""
    session_id: str
    turn_id: int
    role: str  # 'system', 'user', 'assistant', 'incident'
    content: str
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
