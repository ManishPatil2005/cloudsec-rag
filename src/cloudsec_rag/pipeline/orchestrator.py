"""End-to-End CloudSec-RAG Pipeline Orchestrator.

Integrates ingestion, secret scrubbing, prompt injection defense, hybrid RAG retrieval,
LLM reasoning, anti-hallucination verification, 3-tier memory, and executable patching.
"""

import uuid
from typing import Optional
from ..config import settings
from ..core.exceptions import PromptInjectionAttemptError
from ..core.types import CloudSecurityIncident, GroundedAnalysis, IncidentStatus
from ..guardrails.anti_hallucination import AntiHallucinationVerifier
from ..guardrails.injection_detector import InjectionDetector
from ..guardrails.output_validator import OutputValidator
from ..ingestion.parsers import CloudTelemetryParser
from ..ingestion.privacy_scrubber import PrivacyScrubber
from ..llm.factory import LLMProviderFactory
from ..memory.semantic_memory import IncidentSemanticMemory
from ..memory.session_memory import SessionWorkingMemory
from ..memory.sqlite_store import SQLiteEpisodicStore
from ..patching.engine import SecurityPatchingEngine
from ..patching.hitl import HITLApprovalGate
from ..patching.rollback import RollbackGenerator
from ..patching.validator import PatchValidator
from ..rag.retriever import CloudSecRetriever


class CloudSecPipeline:
    """Enterprise orchestrator coordinating multi-cloud security triage and patching."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        llm_provider: Optional[str] = None,
        min_confidence: float = 0.85,
    ):
        self.min_confidence = min_confidence or settings.min_grounding_confidence
        self.db_path = db_path or settings.database_path

        # Subsystems
        self.scrubber = PrivacyScrubber()
        self.parser = CloudTelemetryParser(scrubber=self.scrubber)
        self.injection_detector = InjectionDetector()
        self.retriever = CloudSecRetriever()
        self.anti_hallucination = AntiHallucinationVerifier(min_confidence=self.min_confidence)
        self.output_validator = OutputValidator(min_confidence=self.min_confidence)

        # Patching
        self.patch_validator = PatchValidator()
        self.rollback_gen = RollbackGenerator()
        self.patch_engine = SecurityPatchingEngine(
            validator=self.patch_validator, rollback_gen=self.rollback_gen
        )
        self.hitl_gate = HITLApprovalGate()

        # 3-Tier Memory
        self.sqlite_store = SQLiteEpisodicStore(db_path=self.db_path)
        self.semantic_memory = IncidentSemanticMemory()
        self.sessions = {}

        # LLM Provider
        provider_name = llm_provider or settings.default_llm_provider
        self.llm = LLMProviderFactory.create(provider_name)

    def get_session(self, session_id: str) -> SessionWorkingMemory:
        """Get or initialize working session memory."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionWorkingMemory(session_id=session_id)
        return self.sessions[session_id]

    def analyze_incident(
        self, raw_input: str, session_id: Optional[str] = None, provider_hint: Optional[str] = None
    ) -> GroundedAnalysis:
        """
        Execute full end-to-end triage and remediation pipeline.
        
        Args:
            raw_input: Raw log string, JSON, or YAML manifest.
            session_id: Optional session identifier for working memory.
            provider_hint: Optional hint (AWS, AZURE, GCP, KUBERNETES).
            
        Returns:
            GroundedAnalysis with verified plain language explanation, patch, and rollback plan.
        """
        active_session_id = session_id or f"SESS-{uuid.uuid4().hex[:6].upper()}"
        session = self.get_session(active_session_id)

        # 1. Parse and sanitize telemetry
        incident = self.parser.parse(raw_input, provider_hint=provider_hint)

        # 2. Defense: Adversarial Prompt Injection Guardrail (OWASP LLM 01)
        is_injection, risk_score, matches = self.injection_detector.scan(raw_input)
        incident.injection_risk_score = risk_score
        if is_injection:
            incident.status = IncidentStatus.REJECTED
            self.sqlite_store.save_incident(incident)
            raise PromptInjectionAttemptError(
                f"Adversarial prompt injection pattern detected in cloud log: {matches}",
                pattern=str(matches),
                score=risk_score,
            )

        # 3. Check Tier-3 Semantic Memory for known false-positives
        if self.semantic_memory.is_known_false_positive(incident):
            incident.status = IncidentStatus.SUPPRESSED
            self.sqlite_store.save_incident(incident)
            # Return benign suppression analysis
            analysis = self.output_validator.create_deterministic_fallback(incident, [])
            analysis.plain_language_summary = f"Resource '{incident.resource_id}' is recognized as an approved exception."
            analysis.risk_title = "[SUPPRESSED] Historical False-Positive Exception"
            return analysis

        # 4. Hybrid RAG Retrieval (Grounded in CIS Benchmarks)
        benchmarks = self.retriever.retrieve_grounded_controls(incident, top_k=3)

        # 5. Retrieve Tier-1 conversational context
        context_items = session.get_recent_context()

        # 6. Generate Canary Token & Dispatch to LLM
        canary_token = self.injection_detector.generate_canary()
        
        raw_llm_response = ""
        try:
            raw_llm_response = self.llm.generate_security_analysis(
                incident=incident,
                benchmarks=benchmarks,
                conversation_context=context_items,
                canary_token=canary_token,
            )
        except Exception:
            # Automatic graceful fallback if LLM endpoint fails or network error occurs
            raw_llm_response = ""

        # 7. Canary Token Leakage Check
        if not self.injection_detector.verify_canary_integrity(raw_llm_response, canary_token):
            # Prompt exfiltration attempt detected! Force deterministic fallback
            analysis = self.output_validator.create_deterministic_fallback(incident, benchmarks)
            analysis.root_cause += " [SECURITY NOTE: Canary leakage detected in generative output; safe fallback engaged.]"
        else:
            # 8. Output Validation & Anti-Hallucination Verification
            analysis = self.output_validator.parse_and_validate(raw_llm_response, incident, benchmarks)
            
            # Cross-verify citations and command validity
            is_verified, conf, violations = self.anti_hallucination.verify(
                raw_llm_output=raw_llm_response,
                retrieved_benchmarks=benchmarks,
                parsed_patch=analysis.executable_patch,
            )

            if not is_verified or conf < self.min_confidence:
                # Hallucination detected or low confidence: Engage deterministic fallback
                analysis = self.output_validator.create_deterministic_fallback(incident, benchmarks)

        # 9. Verify Patch & Pair with Rollback
        if analysis.executable_patch:
            # Validate safety
            is_safe, reasons = self.patch_validator.validate(analysis.executable_patch)
            if not is_safe:
                analysis.executable_patch.command = f"# SAFETY WARNING: {reasons[0]}"
            
            # Ensure paired rollback exists
            if not analysis.rollback_plan:
                top_bench = benchmarks[0] if benchmarks else None
                analysis.rollback_plan = self.rollback_gen.generate_rollback(
                    analysis.executable_patch,
                    benchmark_rollback=top_bench.rollback_command if top_bench else None,
                )

        # 10. Persist State in Tier-1, Tier-2, and Tier-3 Memory
        incident.status = IncidentStatus.ANALYZED
        self.sqlite_store.save_incident(incident)
        self.sqlite_store.save_analysis(analysis)

        session.add_interaction(
            role="user",
            content=f"Ingested event: {incident.event_name} on {incident.resource_id}",
            incident_id=incident.incident_id,
        )
        session.add_interaction(
            role="assistant",
            content=analysis.plain_language_summary,
            incident_id=incident.incident_id,
        )

        self.semantic_memory.record_resolution(incident, analysis)

        return analysis
