"""Patch Safety & Blast-Radius Validator.

Inspects generated CLI and IaC commands against destructive operation blacklists
and determines potential infrastructure blast-radius.
"""

import re
from typing import List, Tuple
from ..core.exceptions import PatchValidationFailedError
from ..core.types import BlastRadius, PatchAction


class PatchValidator:
    """Validates command safety, syntax boundaries, and blasts radius."""

    # Explicitly forbidden destructive operations
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
    ]

    # Allowed safe CLI command binaries
    ALLOWED_BINARIES = {"aws", "az", "gcloud", "kubectl", "terraform"}

    def __init__(self):
        self.compiled_blacklist = [re.compile(p) for p in self.DESTRUCTIVE_COMMAND_BLACKLIST]

    def validate(self, patch: PatchAction) -> Tuple[bool, List[str]]:
        """
        Validate safety of patch action.
        
        Returns:
            Tuple of (is_valid, list_of_reasons_if_invalid)
        """
        issues: List[str] = []
        raw_cmd = patch.command.strip()

        if not raw_cmd:
            return False, ["Command string is empty."]

        # Check binary authorization
        lines = [line.strip() for line in raw_cmd.split("\n") if line.strip() and not line.strip().startswith("#")]
        for line in lines:
            # Handle multiple piped or chained commands
            subcmds = re.split(r"&&|\|\||;", line)
            for subcmd in subcmds:
                subcmd = subcmd.strip()
                if not subcmd:
                    continue
                first_token = subcmd.split()[0].lower()
                if first_token not in self.ALLOWED_BINARIES:
                    issues.append(f"Command binary '{first_token}' is not an authorized cloud CLI tool.")

        # Check destructive blacklist
        for pattern in self.compiled_blacklist:
            if pattern.search(raw_cmd):
                issues.append(f"Command violates zero-trust safety policy: matches forbidden pattern '{pattern.pattern}'.")

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
