"""Unit tests for 3-Tier memory system."""

import os
import tempfile
from cloudsec_rag.core.types import CloudProvider, CloudSecurityIncident
from cloudsec_rag.memory.session_memory import SessionWorkingMemory
from cloudsec_rag.memory.sqlite_store import SQLiteEpisodicStore
from cloudsec_rag.memory.semantic_memory import IncidentSemanticMemory


def test_session_sliding_window_memory():
    session = SessionWorkingMemory(session_id="SESS-TEST", max_turns=3)
    for i in range(10):
        session.add_interaction(role="user", content=f"Message {i}")
    
    # Should maintain bounded history (2 * max_turns = 6)
    history = session.get_recent_context()
    assert len(history) <= 6
    assert history[-1].content == "Message 9"


def test_sqlite_episodic_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        store = SQLiteEpisodicStore(db_path=db_path)
        incident = CloudSecurityIncident(
            incident_id="INC-STORE-01",
            provider=CloudProvider.AWS,
            resource_id="bkt-database-backups",
            event_name="PublicBucketAlert",
            raw_payload="test payload",
            sanitized_payload="test payload"
        )
        store.save_incident(incident)

        # Retrieve and verify
        retrieved = store.get_incident("INC-STORE-01")
        assert retrieved is not None
        assert retrieved["resource_id"] == "bkt-database-backups"
        assert retrieved["provider"] == "AWS"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_semantic_false_positive_memory():
    mem = IncidentSemanticMemory()
    incident = CloudSecurityIncident(
        incident_id="INC-FP-01",
        provider=CloudProvider.AWS,
        resource_id="bkt-static-assets-cdn",
        event_name="S3PublicBucket",
        raw_payload="",
        sanitized_payload=""
    )
    
    assert mem.is_known_false_positive(incident) is False
    mem.mark_false_positive(incident, "Approved CDN asset bucket")
    assert mem.is_known_false_positive(incident) is True
