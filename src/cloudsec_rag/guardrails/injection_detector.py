"""Adversarial Prompt Injection & OWASP Top 10 for LLMs Guardrail.

Mitigates LLM01: Prompt Injection, Jailbreak attempts, and System Delimiter Evasion.
Implements Cryptographic Canary Tokens to detect prompt exfiltration.
Hardened against Unicode homoglyphs, zero-width spaces, and leetspeak evasions.
"""

import logging
import re
import secrets
import unicodedata
from typing import List, Optional, Tuple
from ..core.exceptions import PromptInjectionAttemptError

logger = logging.getLogger(__name__)


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
        r"(?i)\b(eval|exec)\s*\([^\)]*\)",
        r"(?i)\bbase64\s+-d\b",
    ]

    # Zero-width characters commonly used to split adversarial keywords
    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]")

    # Common leetspeak substitutions
    LEET_MAP_I = str.maketrans({
        "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"
    })
    LEET_MAP_L = str.maketrans({
        "@": "a", "4": "a", "3": "e", "1": "l", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"
    })

    def __init__(self, sensitivity_threshold: float = 0.35, max_scan_length: int = 65536):
        self.sensitivity_threshold = sensitivity_threshold
        self.max_scan_length = max_scan_length
        self.compiled_patterns = [re.compile(p) for p in self.ADVERSARIAL_PATTERNS]

    def normalize_text(self, text: str) -> str:
        """
        Normalize text to defeat homoglyphs, zero-width splitting, and leetspeak evasions.
        """
        if not text:
            return ""

        # Bound length to protect against ReDoS
        bounded = text[:self.max_scan_length]

        # 1. Unicode decomposition (decompose accented/homoglyph characters)
        normalized = unicodedata.normalize("NFKD", bounded)

        # 2. Strip zero-width and invisible formatting characters
        stripped = self.ZERO_WIDTH_CHARS.sub("", normalized)

        # 3. Collapse multiple whitespace
        collapsed = re.sub(r"\s+", " ", stripped)

        return collapsed

    def scan(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Scan text for prompt injection signatures across raw, normalized, and leet-decoded variants.
        
        Returns:
            Tuple of (is_flagged, risk_score, matched_patterns)
        """
        if not text:
            return False, 0.0, []

        norm_text = self.normalize_text(text)
        leet_i = norm_text.translate(self.LEET_MAP_I)
        # Hybrid leet where leading 1 is 'i' (1gnore -> ignore) and internal 1 is 'l' (a11 -> all)
        hybrid_leet = re.sub(r"\b1", "i", norm_text).translate(self.LEET_MAP_L)

        candidates = [text, norm_text, leet_i, hybrid_leet]

        matches: List[str] = []
        for pattern in self.compiled_patterns:
            for cand in candidates:
                if pattern.search(cand):
                    matches.append(pattern.pattern)
                    break

        # Calculate score: each match contributes 0.4 up to 1.0
        score = min(1.0, len(matches) * 0.4)
        is_flagged = len(matches) > 0 and score >= self.sensitivity_threshold

        if is_flagged:
            logger.warning(
                "Adversarial prompt injection signature detected: %s (risk_score=%.2f)",
                matches, score
            )

        return is_flagged, round(score, 2), matches

    def generate_canary(self) -> str:
        """Generate a random cryptographic canary token."""
        return f"CANARY_{secrets.token_hex(8)}"

    def verify_canary_integrity(self, llm_response: Optional[str], expected_canary: str) -> bool:
        """
        Verify that the LLM response has NOT leaked the canary token.
        Case-insensitive and safe against null/non-string inputs.
        """
        if not expected_canary:
            return True
        if not llm_response or not isinstance(llm_response, str):
            return True
        return expected_canary.lower() not in llm_response.lower()
