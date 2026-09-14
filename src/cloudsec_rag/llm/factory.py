"""Factory for creating LLM provider instances."""

import os
from .base import BaseLLMProvider
from .gemini_provider import GeminiLLMProvider
from .mock_provider import MockLLMProvider


class LLMProviderFactory:
    """Instantiates the appropriate LLM provider based on settings or environment."""

    @staticmethod
    def create(provider_name: str = "mock") -> BaseLLMProvider:
        prov = provider_name.lower().strip()
        if prov == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                # Graceful fallback to mock if no API key is set
                return MockLLMProvider()
            return GeminiLLMProvider(api_key=api_key)
        return MockLLMProvider()
