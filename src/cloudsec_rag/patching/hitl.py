"""Human-in-the-Loop (HITL) Approval & Sign-Off Gate.

Prevents unauthorized automatic execution of cloud modifications without
explicit operator validation and cryptographic audit trail.
"""

import uuid
from datetime import datetime
from typing import Optional
from ..core.types import HITLDecision, PatchAction


class HITLApprovalGate:
    """Manages manual operator reviews, approvals, and rejections of patches."""

    def review_patch(
        self,
        incident_id: str,
        patch: PatchAction,
        decision_str: str,
        operator_id: str,
        notes: Optional[str] = None,
    ) -> HITLDecision:
        """Process operator sign-off decision."""
        normalized_decision = decision_str.strip().upper()
        if normalized_decision not in {"APPROVED", "REJECTED"}:
            normalized_decision = "REJECTED"

        return HITLDecision(
            decision_id=f"HITL-{uuid.uuid4().hex[:8].upper()}",
            incident_id=incident_id,
            patch_id=patch.patch_id,
            decision=normalized_decision,
            operator_id=operator_id,
            notes=notes or ("Approved by operator for execution" if normalized_decision == "APPROVED" else "Rejected by operator"),
            timestamp=datetime.utcnow(),
        )
