# CloudSec-RAG Enterprise Security & Governance Rules (v2.0)

This document establishes the binding security rules, guardrails, and operational boundaries governing the CloudSec-RAG platform, including its multi-cloud ingestion engine, Graph-RAG orchestrator, AST patch synthesizer, and AI Security Copilot.

---

## 1. Core Security Rules & Guardrails

### Rule 1: Zero Adversarial Prompt Injection (LLM01 / LLM02)
- **Policy:** Untrusted user input, raw log payloads, and chat queries are strictly isolated using delimiter boundaries (`<untrusted_cloud_log>...</untrusted_cloud_log>`) and cryptographic canary tokens.
- **Enforcement:** Every incoming request to `/api/v1/copilot/chat`, `/api/v1/analyze`, and `/api/v2/analyze` passes through `InjectionDetector`.
- **Blocked Vectors:**
  - Direct instruction overrides (`"ignore previous instructions"`, `"disregard all rules"`).
  - Jailbreak impersonations (`"DAN"`, `"jailbroken"`, `"exploit bot"`).
  - System prompt or canary token extraction attempts.
  - Remote code execution strings (`"rm -rf /"`, `"curl | bash"`, SQL/NoSQL injections).
- **Action:** Any prompt injection attempt triggers an HTTP 400 rejection with an audit event recorded in the security log.

---

### Rule 2: Automatic PII & Credential Scrubbing (Data Loss Prevention)
- **Policy:** Cloud telemetry frequently contains confidential tokens, private API keys, and internal IP allocations. Telemetry must never enter the vector database or LLM prompts in plain text.
- **Enforcement:** The `PrivacyScrubber` engine regex-sanitizes:
  - AWS Access Key IDs (`AKIA...`) and Secret Keys.
  - Azure Shared Access Signatures (SAS) and Subscription IDs.
  - GCP Service Account JSON keys and private keys.
  - Bearer tokens, JWTs, and authorization headers.
  - IPv4/IPv6 private ranges (anonymized where appropriate).
  - Corporate email addresses and account identifiers.
- **Action:** Credentials are replaced with cryptographic hashes or tokenized masks (`[REDACTED_AWS_KEY]`) prior to ingestion.

---

### Rule 3: Zero-Hallucination Grounding Rule
- **Policy:** The AI engine and Copilot are forbidden from inventing fictitious CLI commands, fabricated parameters, or nonexistent CIS benchmarks.
- **Enforcement:**
  - Grounding confidence threshold is strictly enforced at $\ge 0.85$.
  - All recommendations must cite verified references from indexed CIS Benchmarks (AWS v3.0, Azure v2.0, GCP v3.0, K8s v1.8), NIST SP 800-53 Rev. 5, or MITRE ATT&CK Cloud.
  - If grounding confidence falls below the threshold, the system immediately switches to deterministic static fallback rules.

---

### Rule 4: Blast-Radius Constrained AST Patching & Execution Boundary
- **Policy:** The platform and Copilot cannot directly execute arbitrary bash commands or unverified shell scripts on host infrastructure.
- **Enforcement:**
  - Remediation diffs are generated exclusively through Abstract Syntax Tree (AST) transformations on Terraform (HCL) and Kubernetes YAML manifests.
  - Pre-patch and post-patch state diffs are evaluated by the `BlastRadiusSimulator`.
  - Disruption probability is calculated across downstream dependency graphs.
  - Every patch is accompanied by a mathematically paired inverse rollback plan.

---

### Rule 5: Dual-Control Human-in-the-Loop (HITL) Gate
- **Policy:** No automated remediation can be applied to production cloud assets without human authorization.
- **Enforcement:**
  - High and Critical severity incidents require cryptographic confirmation via `/api/v1/hitl/decision`.
  - High blast-radius remediations ($>15\%$ disruption risk) require multi-factor dual-role authorization.
  - Operators can accept, reject, or request modification directly from the dashboard.

---

### Rule 6: Incident & Problem Reporting Standard
- **Policy:** Users, SOC analysts, and automated monitoring agents have a standardized procedure to report operational bugs, false positives, and unexpected reachability verdicts.
- **Triage Protocol:**
  1. **False-Positive Claim:** Analyst submits the raw log ID and reachability trace to the AI Copilot using `Report False Positive`.
  2. **Rule Verification:** The engine generates an audit diff comparing observed topology against expected policy.
  3. **Diagnostic Bundle:** Incident metadata, anonymized payload, and BFS reachability graph are archived to `data/sessions/cloudsec_memory.db`.
  4. **Escalation:** Critical disputes are escalated to the SOC Lead with cryptographic evidence hashes.

---

### Rule 7: Air-Gapped Privacy & Memory Hygiene
- **Policy:** Tenant telemetry is isolated and ephemeral.
- **Enforcement:**
  - Conversational memory is bounded by a strict sliding window (maximum 10 conversational turns) via `SessionWorkingMemory`.
  - The dashboard auto-purges prior state between analysis runs (`resetDashboardState()`).
  - The platform operates offline with zero external network connectivity using local deterministic SLM reasoning when cloud LLM endpoints are unavailable.

---

## 2. Interactive AI Copilot Rules for Dashboard Assistance

When users interact with the dashboard AI Copilot, the Copilot operates under these operational guidelines:

| Query Type | Copilot Behavior & Rules |
| :--- | :--- |
| **Execution Guidance** | Step-by-step instructions on running Mode 1 (Deterministic Simulation) or Mode 2 (Manual Log Analysis), setting up CLI commands, or launching the server on custom ports. |
| **Alert Explanation** | Explains why an alert is Critical vs. Benign, how the reachability graph proved the attack path, and how the CIS benchmark applies. |
| **Patch & Rollback Support** | Explains the Terraform/HCL patch diff, describes the blast radius impact, and details how the rollback plan restores prior state. |
| **Problem / Bug Reporting** | Collects incident ID, anomalous behavior, and diagnostic details; formats an actionable incident report for the engineering team. |
| **Out-of-Scope / Malicious Query** | Politely refuses non-cloud-security queries and immediately flags prompt injection or credential exfiltration attempts. |
