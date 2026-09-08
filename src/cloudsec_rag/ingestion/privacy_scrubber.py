"""Enterprise Privacy Scrubber & Sensitive Credential Redactor.

Ensures zero secret or PII leakage before data reaches LLM prompt composition
or vector embedding layers.
"""

import re
import hashlib
from typing import Dict, Tuple


class PrivacyScrubber:
    """Detects, redacts, and pseudonymizes sensitive cloud credentials and PII."""

    # Pre-compiled high-precision security patterns
    PATTERNS = {
        "aws_access_key": (
            re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
            "<REDACTED_AWS_ACCESS_KEY:***>",
        ),
        "aws_secret_key": (
            re.compile(r"(?i)(?:aws_secret_access_key|secret_key|secretaccesskey)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
            "aws_secret_access_key=<REDACTED_AWS_SECRET:***>",
        ),
        "jwt_token": (
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
            "<REDACTED_JWT_TOKEN:***>",
        ),
        "private_key": (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "<REDACTED_PRIVATE_KEY_BLOCK>",
        ),
        "db_connection_uri": (
            re.compile(r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:(?:[^@\s]+)@"),
            r"\1://[REDACTED_USER]:[REDACTED_PASSWORD]@",
        ),
        "generic_password": (
            re.compile(r"(?i)(password|passwd|pwd|client_secret|api_key|secret)[\s:=]+['\"]?([A-Za-z0-9!@#$%^&*()_+=\-`~\[\]{}|;:,.<>?]{6,64})['\"]?"),
            r"\1=<REDACTED_SECRET:***>",
        ),
        "email_address": (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
            "<REDACTED_EMAIL>",
        ),
        "bearer_token": (
            re.compile(r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
            "Bearer <REDACTED_BEARER_TOKEN>",
        )
    }

    def __init__(self, salt: str = "cloudsec-enterprise-salt"):
        self.salt = salt

    def scrub(self, text: str) -> Tuple[str, int, Dict[str, int]]:
        """
        Scrub all sensitive keys, tokens, and PII from the input string.
        
        Returns:
            Tuple of (sanitized_text, total_redactions_count, breakdown_dict)
        """
        if not text:
            return "", 0, {}

        sanitized = text
        total_count = 0
        breakdown: Dict[str, int] = {}

        for name, (regex, replacement) in self.PATTERNS.items():
            matches = list(regex.finditer(sanitized))
            if matches:
                count = len(matches)
                total_count += count
                breakdown[name] = count
                sanitized = regex.sub(replacement, sanitized)

        return sanitized, total_count, breakdown

    def pseudonymize_identifier(self, identifier: str) -> str:
        """Deterministically pseudonymize internal IDs (e.g. account numbers or private hostnames)."""
        hashed = hashlib.sha256((identifier + self.salt).encode("utf-8")).hexdigest()[:12]
        return f"ANON-{hashed}"
