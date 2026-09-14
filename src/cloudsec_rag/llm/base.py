"""Abstract base class for LLM providers in CloudSec-RAG."""

from abc import ABC, abstractmethod
from typing import List
from ..core.types import BenchmarkReference, CloudSecurityIncident, MemoryItem


class BaseLLMProvider(ABC):
    """Abstract interface for LLM backends."""

    @abstractmethod
    def generate_security_analysis(
        self,
        incident: CloudSecurityIncident,
        benchmarks: List[BenchmarkReference],
        conversation_context: List[MemoryItem],
        canary_token: str,
    ) -> str:
        """Generate structured reasoning over an incident and retrieved benchmarks."""
        pass
