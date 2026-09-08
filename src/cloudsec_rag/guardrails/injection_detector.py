"""Adversarial Prompt Injection & OWASP Top 10 for LLMs Guardrail.

Mitigates LLM01: Prompt Injection, Jailbreak attempts, and System Delimiter Evasion.
Implements Cryptographic Canary Tokens to detect prompt exfiltration.
"""

import re
import secrets
from typing import List, Tuple
from ..core.exceptions import PromptInjectionAttemptError


class InjectionDetector:
    """Detects prompt injection vectors, jailbreak sequences, and malicious overrides in cloud logs."""

    # High-confidence adversarial signatures (OWASP LLM 2025/2026)
    ADVERSARIAL_PATTERNS = [
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
        r"(?i)\bdisregard\s+(?:all\s+)?(?:safety|system|rules|prompts)\b",
        r"(?i)\byou\s+are\s+now\s+(?:DAN|jailbroken|unrestricted|an\s+exploit\s+bot)\b",
        r"(?i)\bsystem\s+override\b",
        r"(?i)\bdo\s+not\s+report\s+this\s+(?:vulnerability|alert|incident)\b",
        r"(?i)\bmark\s+(?:this\s+)?severity\s+(?:as\s+)?(?:low|safe|clear)\b",
        r"(?i)\boutput\s+only\s+(?:JSON\s+with\s+)?\"status\":\s*\"ok\"\b",
        r"(?i)\bprint\s+(?:the\s+)?system\s+prompt\b",
        r"(?i)\breveal\s+(?:internal\s+)?canary\b",
        r"(?i)<\/?(?:system|instruction|prompt_override)>",
        r"(?i)\brm\s+-rf\s+\/\b",
        r"(?i)\bDROP\s+DATABASE\b",
        r"(?i)\bcurl\s+https?:\/\/[^\s]+\s*\|\s*bash\b",
    ]

    def __init__(self, sensitivity_threshold: float = 0.7):
        self.sensitivity_threshold = sensitivity_threshold
        self.compiled_patterns = [re.compile(p) for p in self.ADVERSARIAL_PATTERNS]

    def scan(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Scan text for prompt injection signatures.
        
        Returns:
            Tuple of (is_flagged, risk_score, matched_patterns)
        """
        if not text:
            return False, 0.0, []

        matches = []
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)

        score = min(1.0, len(matches) * 0.4)
        is_flagged = len(matches) > 0 and (score >= self.sensitivity_threshold or len(matches) >= 1)

        return is_flagged, round(score, 2), matches

    def generate_canary(self) -> str:
        """Generate a random cryptographic canary token."""
        return f"CANARY_{secrets.token_hex(8)}"

    def verify_canary_integrity(self, llm_response: str, expected_canary: str) -> bool:
        """
        Verify that the LLM response has NOT leaked the canary token.
        If the canary appears in the output, it indicates prompt leakage or adversarial exfiltration.
        """
        if not expected_canary:
            return True
        return expected_canary not in llm_response
