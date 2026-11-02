"""Patch Safety & Blast-Radius Validator.

Inspects generated CLI and IaC commands against destructive operation blacklists,
shell injection vectors (pipes, subshells), and unauthorized binary executions.
"""

import re
import shlex
from typing import List, Tuple
from ..core.exceptions import PatchValidationFailedError
from ..core.types import BlastRadius, PatchAction


class PatchValidator:
    """Validates command safety, syntax boundaries, and blast radius."""

    # Explicitly forbidden destructive operations across AWS, Azure, GCP, and K8s
    DESTRUCTIVE_COMMAND_BLACKLIST = [
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bdelete-vpc\b",
        r"(?i)\bdelete-cluster\b",
        r"(?i)\bterminate-instances\b",
        r"(?i)\bdrop\s+database\b",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\bformat\s+[a-z]:\b",
        r"(?i)\bdelete-subscription\b",
        r"(?i)\bdestroy\b",
        r"(?i)\bdelete-db-instance\b",
        r"(?i)\bdelete-role\b",
        r"(?i)\bgroup\s+delete\b",
        r"(?i)\bvm\s+delete\b",
        r"(?i)\baks\s+delete\b",
        r"(?i)\bprojects\s+delete\b",
        r"(?i)\bdelete\s+namespace\b",
        r"(?i)\bdelete\s+all\s+--all\b",
    ]

    # Dangerous shell injection patterns (subshells, piping to interpreters, command substitution)
    SHELL_INJECTION_PATTERNS = [
        r"\$\([^\)]+\)",                       # Command substitution $(cmd)
        r"`[^`]+`",                            # Backtick substitution `cmd`
        r"\|\s*(?:ba|z|c|da|k)?sh\b",          # Pipe to shell | sh, | bash
        r"\|\s*python[0-9.]*\b",               # Pipe to python
        r"\|\s*powershell\b",                  # Pipe to powershell
        r">\s*\/etc\/",                        # Redirection to system directories
    ]

    # Allowed safe CLI command binaries
    ALLOWED_BINARIES = {"aws", "az", "gcloud", "kubectl", "terraform"}

    def __init__(self):
        self.compiled_blacklist = [re.compile(p) for p in self.DESTRUCTIVE_COMMAND_BLACKLIST]
        self.compiled_injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.SHELL_INJECTION_PATTERNS]

    def validate(self, patch: PatchAction) -> Tuple[bool, List[str]]:
        """
        Validate safety of patch action across CLI commands and IaC templates.
        
        Returns:
            Tuple of (is_valid, list_of_reasons_if_invalid)
        """
        issues: List[str] = []
        raw_cmd = patch.command.strip()

        if not raw_cmd:
            return False, ["Command string is empty."]

        # 1. Check for Shell Injection / Command Substitution in CLI
        for pattern in self.compiled_injection_patterns:
            if pattern.search(raw_cmd):
                issues.append(f"Command contains forbidden shell injection pattern: '{pattern.pattern}'.")

        # 2. Check binary authorization
        lines = [line.strip() for line in raw_cmd.split("\n") if line.strip() and not line.strip().startswith("#")]
        for line in lines:
            # Handle multiple chained commands (&&, ||, ;, and |)
            subcmds = re.split(r"&&|\|\||;|\|", line)
            for subcmd in subcmds:
                subcmd = subcmd.strip()
                if not subcmd:
                    continue
                first_token = subcmd.split()[0].lower()
                if first_token not in self.ALLOWED_BINARIES:
                    issues.append(f"Command binary '{first_token}' is not an authorized cloud CLI tool.")

        # 3. Check destructive blacklist against CLI command
        for pattern in self.compiled_blacklist:
            if pattern.search(raw_cmd):
                issues.append(f"Command violates zero-trust safety policy: matches forbidden pattern '{pattern.pattern}'.")

        # 4. Check destructive blacklist against IaC template
        if patch.iac_code:
            for pattern in self.compiled_blacklist:
                if pattern.search(patch.iac_code):
                    issues.append(f"IaC template violates zero-trust safety policy: matches forbidden pattern '{pattern.pattern}'.")

        is_valid = len(issues) == 0
        return is_valid, issues

    def estimate_blast_radius(self, command: str) -> BlastRadius:
        """Estimate operational impact blast radius."""
        cmd_lower = command.lower()
        if any(w in cmd_lower for w in ["put-public-access-block", "network nsg rule delete", "security-group-ingress", "patch deployment"]):
            return BlastRadius.HIGH
        if any(w in cmd_lower for w in ["attach-role-policy", "detach-role-policy", "update-iam-policy", "bucket-level-access"]):
            return BlastRadius.MEDIUM
        return BlastRadius.LOW
