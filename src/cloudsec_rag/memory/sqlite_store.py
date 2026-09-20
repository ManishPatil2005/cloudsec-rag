"""Tier 2: ACID Persistent SQLite Episodic Memory Store.

Guarantees zero memory loss across application restarts, container redeployments,
and multi-shift SOC handovers.
"""

from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..core.types import CloudSecurityIncident, GroundedAnalysis, HITLDecision, MemoryItem


class SQLiteEpisodicStore:
    """Persistent SQLite database maintaining audit trails and incident triage states."""

    def __init__(self, db_path: str = "data/sessions/cloudsec_memory.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connection(self):
        """Context manager that guarantees connection is closed on exit."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize relational database tables."""
        with self._connection() as conn:
            cursor = conn.cursor()
            
            # Incidents table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                event_name TEXT NOT NULL,
                region TEXT,
                severity TEXT,
                status TEXT,
                sanitized_payload TEXT,
                secrets_redacted_count INTEGER DEFAULT 0,
                detected_at TIMESTAMP,
                metadata_json TEXT
            );
            """)

            # Analyses & Patches table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                incident_id TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                risk_title TEXT NOT NULL,
                severity TEXT NOT NULL,
                plain_language_summary TEXT NOT NULL,
                root_cause TEXT,
                technical_breakdown TEXT,
                compliance_mappings TEXT,
                grounding_confidence REAL,
                is_fallback INTEGER,
                executable_patch_json TEXT,
                rollback_plan_json TEXT,
                analyzed_at TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
            );
            """)

            # Human-in-the-Loop Audit Log table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS hitl_audit (
                decision_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                patch_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                notes TEXT,
                timestamp TIMESTAMP
            );
            """)

            # Conversation Memory Turns table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                incident_id TEXT,
                timestamp TIMESTAMP
            );
            """)

            conn.commit()

    def save_incident(self, incident: CloudSecurityIncident) -> None:
        """Persist or update an incident."""
        with self._connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO incidents (
                incident_id, provider, resource_id, event_name, region,
                severity, status, sanitized_payload, secrets_redacted_count,
                detected_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.provider.value,
                incident.resource_id,
                incident.event_name,
                incident.region,
                incident.severity_hint.value,
                incident.status.value,
                incident.sanitized_payload,
                incident.secrets_redacted_count,
                incident.detected_at.isoformat(),
                json.dumps(incident.metadata),
            ))
            conn.commit()

    def save_analysis(self, analysis: GroundedAnalysis) -> None:
        """Persist full grounded analysis and patch information."""
        with self._connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO analyses (
                incident_id, resource_id, risk_title, severity, plain_language_summary,
                root_cause, technical_breakdown, compliance_mappings, grounding_confidence,
                is_fallback, executable_patch_json, rollback_plan_json, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis.incident_id,
                analysis.resource_id,
                analysis.risk_title,
                analysis.severity.value,
                analysis.plain_language_summary,
                analysis.root_cause,
                analysis.technical_breakdown,
                json.dumps(analysis.compliance_mappings),
                analysis.grounding_confidence,
                1 if analysis.is_deterministic_fallback else 0,
                analysis.executable_patch.model_dump_json() if analysis.executable_patch else None,
                analysis.rollback_plan.model_dump_json() if analysis.rollback_plan else None,
                analysis.analyzed_at.isoformat(),
            ))
            conn.commit()

    def save_hitl_decision(self, decision: HITLDecision) -> None:
        """Record Human-in-the-Loop decision in immutable audit log."""
        with self._connection() as conn:
            conn.execute("""
            INSERT INTO hitl_audit (
                decision_id, incident_id, patch_id, decision, operator_id, notes, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.decision_id,
                decision.incident_id,
                decision.patch_id,
                decision.decision,
                decision.operator_id,
                decision.notes,
                decision.timestamp.isoformat(),
            ))
            new_status = "APPROVED" if decision.decision == "APPROVED" else "REJECTED"
            conn.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, decision.incident_id))
            conn.commit()

    def save_turn(self, item: MemoryItem) -> None:
        """Append a conversational turn to episodic store."""
        with self._connection() as conn:
            conn.execute("""
            INSERT INTO session_turns (session_id, turn_id, role, content, incident_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                item.session_id,
                item.turn_id,
                item.role,
                item.content,
                item.incident_id,
                item.timestamp.isoformat(),
            ))
            conn.commit()

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full incident record by ID."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            return dict(row) if row else None

    def get_recent_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve latest incidents for dashboard."""
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_analysis(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis record by incident ID."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM analyses WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("compliance_mappings"):
                res["compliance_mappings"] = json.loads(res["compliance_mappings"])
            if res.get("executable_patch_json"):
                res["executable_patch"] = json.loads(res["executable_patch_json"])
            if res.get("rollback_plan_json"):
                res["rollback_plan"] = json.loads(res["rollback_plan_json"])
            return res
