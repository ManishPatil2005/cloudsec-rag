"""Anti-Hallucination & Factual Grounding Verifier.

Cross-verifies model claims, citations, and generated commands against authoritative
ground-truth benchmarks to achieve zero-hallucination cloud remediation.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from ..core.types import BenchmarkReference, GroundedAnalysis, PatchAction


class AntiHallucinationVerifier:
    """Verifies citation validity, command grounding, and factual alignment with retrieved benchmarks."""

    def __init__(self, min_confidence: float = 0.85):
        self.min_confidence = min_confidence

    def verify(
        self,
        raw_llm_output: str,
        retrieved_benchmarks: List[BenchmarkReference],
        parsed_patch: Optional[PatchAction] = None,
    ) -> Tuple[bool, float, List[str]]:
        """
        Verify that LLM output is strictly grounded in retrieved benchmarks.
        
        Returns:
            Tuple of (is_verified, grounding_confidence_score, list_of_violations)
        """
        violations: List[str] = []
        valid_citation_ids: Set[str] = {b.citation_id for b in retrieved_benchmarks}

        # 1. Extract all claimed citations from LLM output (e.g. [REF: CIS-AWS-2.1.5] or CIS-AWS-2.1.5)
        claimed_citations = self._extract_citations(raw_llm_output)

        if not claimed_citations and retrieved_benchmarks:
            violations.append("Output contains zero citation references to retrieved benchmarks.")

        # Check for hallucinated / fabricated citation IDs
        for citation in claimed_citations:
            if citation not in valid_citation_ids:
                violations.append(
                    f"Hallucinated citation detected: '{citation}' is not in retrieved ground-truth benchmarks."
                )

        # 2. Command Grounding Verification
        if parsed_patch and parsed_patch.command:
            is_cmd_grounded = self._verify_command_grounding(parsed_patch.command, retrieved_benchmarks)
            if not is_cmd_grounded:
                violations.append(
                    f"Generated command '{parsed_patch.command}' contains unverified cloud CLI syntax or flags not supported by benchmarks."
                )

        # 3. Compute Grounding Confidence
        if violations:
            confidence = max(0.2, 1.0 - (len(violations) * 0.35))
            is_verified = False
        else:
            # Baseline high confidence when citations match and no violations exist
            confidence = max(0.92, retrieved_benchmarks[0].similarity_score if retrieved_benchmarks else 0.88)
            is_verified = confidence >= self.min_confidence

        return is_verified, round(confidence, 3), violations

    def _extract_citations(self, text: str) -> List[str]:
        """Find citation identifiers in text."""
        # Matches patterns like CIS-AWS-2.1.5, NIST-AC-3, MITRE-ATTACK-T1530
        pattern = r"\b(?:CIS-[A-Z]+-[0-9\.]+|NIST-[A-Z0-9\-]+|MITRE-[A-Z0-9\-]+)\b"
        return list(set(re.findall(pattern, text)))

    def _verify_command_grounding(self, command: str, benchmarks: List[BenchmarkReference]) -> bool:
        """Check if core command binary and primary action exist in any benchmark remediation."""
        cmd_tokens = set(re.findall(r"[a-zA-Z0-9_\-]+", command.lower()))
        for b in benchmarks:
            bench_tokens = set(re.findall(r"[a-zA-Z0-9_\-]+", b.remediation_command.lower()))
            overlap = cmd_tokens.intersection(bench_tokens)
            # If at least 2 significant cloud command tokens match (e.g., "aws", "s3api", "put-public-access-block")
            if len(overlap) >= 2:
                return True
        return False
