"""Domain exceptions for CloudSec-RAG."""


class CloudSecBaseException(Exception):
    """Base exception for all CloudSec-RAG errors."""
    pass


class PromptInjectionAttemptError(CloudSecBaseException):
    """Raised when an adversarial prompt injection attempt is detected in cloud telemetry or input."""
    def __init__(self, message: str, pattern: str = "", score: float = 1.0):
        super().__init__(message)
        self.pattern = pattern
        self.score = score


class SecretLeakageDetectedError(CloudSecBaseException):
    """Raised when unredacted secrets or credentials threaten to escape into untrusted environments."""
    def __init__(self, message: str, secret_type: str = ""):
        super().__init__(message)
        self.secret_type = secret_type


class HallucinationError(CloudSecBaseException):
    """Raised when LLM output lacks factual grounding or valid benchmark citations."""
    def __init__(self, message: str, hallucination_score: float = 1.0, missing_citations: list = None):
        super().__init__(message)
        self.hallucination_score = hallucination_score
        self.missing_citations = missing_citations or []


class PatchValidationFailedError(CloudSecBaseException):
    """Raised when a generated remediation patch fails syntax or blast-radius safety checks."""
    def __init__(self, message: str, command: str = "", reason: str = ""):
        super().__init__(message)
        self.command = command
        self.reason = reason


class MemoryConsistencyError(CloudSecBaseException):
    """Raised when persistent memory state is corrupted or fails integrity checks."""
    pass
