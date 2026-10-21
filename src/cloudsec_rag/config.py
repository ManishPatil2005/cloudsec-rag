"""Configuration settings for CloudSec-RAG."""

import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv()

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SESSIONS_DIR = DATA_DIR / "sessions"
BENCHMARKS_DIR = DATA_DIR / "benchmarks"


class Settings(BaseModel):
    app_env: str = Field(default="development")
    app_port: int = Field(default=8000)
    app_host: str = Field(default="0.0.0.0")
    log_level: str = Field(default="INFO")

    # LLM Settings
    default_llm_provider: str = Field(
        default_factory=lambda: os.getenv("DEFAULT_LLM_PROVIDER", "gemini" if os.getenv("GEMINI_API_KEY") else "mock")
    )  # 'mock', 'gemini', 'openai'
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    openai_api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))

    # Security & Guardrails
    min_grounding_confidence: float = Field(default=0.85)
    strict_citation_enforcement: bool = Field(default=True)
    prompt_injection_shield_enabled: bool = Field(default=True)
    privacy_scrubber_enabled: bool = Field(default=True)

    # Memory & Database
    database_path: str = Field(default_factory=lambda: str(SESSIONS_DIR / "cloudsec_memory.db"))
    max_working_memory_turns: int = Field(default=10)


settings = Settings()

# Ensure directories exist
os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(BENCHMARKS_DIR, exist_ok=True)
