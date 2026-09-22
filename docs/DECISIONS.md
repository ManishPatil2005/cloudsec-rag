# Architecture Decision Records (ADRs)

## Product: CloudSec-RAG

---

## ADR-001: Hybrid BM25 + Dense Semantic Retrieval
- **Status:** Accepted
- **Context:** Cloud security logs contain exact technical codes (e.g., `s3:PutBucketPolicy`, `CIS 1.20`, `CVE-2024-21626`, `ap-south-1`) alongside natural language descriptions. Pure dense vector search often misses exact alphanumeric error codes, while pure BM25 fails to match conceptual queries like "unencrypted storage".
- **Decision:** Use a Hybrid Retrieval architecture combining BM25 lexical token matching and Dense Vector Cosine Similarity fused via Reciprocal Rank Fusion (RRF).
- **Consequence:** 100% recall on specific CIS control IDs and high semantic relevance on general queries.

---

## ADR-002: Deterministic Fallback on Low Grounding Confidence
- **Status:** Accepted
- **Context:** When LLMs face unfamiliar cloud telemetry, they risk hallucinating fake CLI commands or insecure IAM configurations.
- **Decision:** If the anti-hallucination evaluator scores factual consistency or citation alignment below 0.85, the system automatically swaps out generative text for a cryptographically verified deterministic CIS remediation template.
- **Consequence:** Absolute elimination of ungrounded or fabricated shell commands.

---

## ADR-003: Three-Tier Persistent Memory vs. Stateless Requests
- **Status:** Accepted
- **Context:** Enterprise security operations require continuity. Analysts cannot afford to lose the context of an incident during shift handovers, nor should the system give conflicting remediation advice for the same recurring misconfiguration.
- **Decision:** Implement a three-tier memory architecture:
  1. Tier 1: In-memory sliding window for active conversation.
  2. Tier 2: SQLite database for persistent session storage and checkpoints.
  3. Tier 3: Semantic memory graph for past incidents, verified patches, and false positives.
- **Consequence:** Complete memory retention across restarts, container rebuilds, and operator handovers.

---

## ADR-004: Ingestion-Time Secret Scrubber before LLM Dispatches
- **Status:** Accepted
- **Context:** Sending live production cloud logs with live AWS credentials, session tokens, or private customer data to any LLM endpoint violates compliance (GDPR, HIPAA, SOC 2).
- **Decision:** Implement a deterministic redaction pipeline (`PrivacyScrubber`) that scrubs and HMAC-pseudonymizes sensitive tokens before any embedding or prompt generation occurs.
- **Consequence:** Zero leakage of cloud credentials or PII.

---

## ADR-005: Paired Automated Rollback Script Requirement
- **Status:** Accepted
- **Context:** If a security patch breaks a mission-critical cloud application (e.g., shutting down a production load balancer port), teams need an instant one-click rollback.
- **Decision:** Every generated patch must include an automated inverse rollback command/configuration generated simultaneously and validated for syntax.
- **Consequence:** Safe, recoverable remediation for production environments.
