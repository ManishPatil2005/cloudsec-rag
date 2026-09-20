"""Tier 1: High-Speed Working Session Memory.

Maintains sliding-window multi-turn conversational context with strict token bounds.
"""

from typing import List
from ..core.types import MemoryItem


class SessionWorkingMemory:
    """Sliding-window in-memory conversational store for active triage sessions."""

    def __init__(self, session_id: str, max_turns: int = 10):
        self.session_id = session_id
        self.max_turns = max_turns
        self.history: List[MemoryItem] = []
        self._turn_counter = 0

    def add_interaction(self, role: str, content: str, incident_id: str = None, metadata: dict = None) -> MemoryItem:
        """Add an interaction turn to the active session."""
        self._turn_counter += 1
        item = MemoryItem(
            session_id=self.session_id,
            turn_id=self._turn_counter,
            role=role,
            content=content,
            incident_id=incident_id,
            metadata=metadata or {}
        )
        self.history.append(item)

        # Sliding window pruning
        if len(self.history) > (self.max_turns * 2):
            self.history = self.history[-(self.max_turns * 2):]

        return item

    def get_recent_context(self) -> List[MemoryItem]:
        """Return currently retained conversation history."""
        return list(self.history)

    def clear(self) -> None:
        """Clear active working memory."""
        self.history.clear()
        self._turn_counter = 0
