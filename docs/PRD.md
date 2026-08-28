# Product Requirements Document (PRD)

## Product: CloudSec-RAG (Enterprise AI Cloud Security & Remediation Platform)
**Version:** 1.0.0-PROD  
**Author:** Manish Pundlik Patil (Ref: B.Tech CSE Semester Project, NLP)  
**Target Audience:** SOC Analysts, Cloud SecOps, Platform Engineers at Tech Giants, SMBs & Academic Researchers  

---

## 1. Problem Statement
Cloud infrastructure across major providers (AWS, Azure, GCP, Kubernetes) produces millions of events, alerts, and configuration drifts every day. According to Gartner, **80% to 99% of cloud security breaches originate from simple misconfigurations** (e.g., publicly accessible S3 buckets, permissive IAM wildcard privileges, exposed Kubernetes API servers) rather than novel zero-day exploits.

Traditional cloud security posture management (CSPM) and SIEM tools present severe pain points:
1. **Cryptic Alerts & Cognitive Overload:** Raw logs (e.g., `WARN: s3_bucket_policy=PUBLIC_READ code=CFG-0091`) require manual lookup and interpretation under high stress.
2. **Hallucination Danger in LLM Assistants:** Generic generative models frequently invent non-existent flags, faulty IAM policies, or hallucinated commands that can cause catastrophic cloud outages.
3. **Adversarial Vulnerabilities & Privacy Risks:** Attackers inject prompt injection payloads (OWASP Top 10 for LLM #1) into cloud logs to trick LLMs into executing malicious scripts or leaking credentials.
4. **Context & Memory Loss:** Security incident triage often spans multiple shifts and queries; standard LLMs suffer from context window amnesia and lack persistent incident tracking.
5. **Lack of Safe, Executable Patching:** Alerts describe the problem but fail to provide validated, idempotent Infrastructure-as-Code (IaC) or CLI remediation scripts with safety checks, blast-radius analysis, and automated rollbacks.

---

## 2. Product Vision & Goals
CloudSec-RAG is an enterprise-grade, hallucination-resistant, zero-leakage LLM + RAG reasoning and remediation engine. It bridges raw multi-cloud telemetry with natural-language explanation, deterministic citation grounding, three-tier persistent memory, adversarial guardrails, and executable multi-cloud security patching.

### Core Objectives
1. **Zero-Hallucination Plain Language Translation:** Convert multi-cloud alerts into plain English (clear risk, root cause, severity, impact) grounded strictly in authoritative security standards (CIS Benchmarks, NIST SP 800-53, MITRE ATT&CK Cloud Matrix).
2. **Strict Grounding & Citation Verification:** Enforce citation token checks; if an LLM suggestion lacks backing evidence from verified benchmarks, mark as `UNCERTAIN` and refuse blind destructive remediation.
3. **Persistent Memory Loss Protection:** Provide a 3-tier memory engine (working session sliding window + ACID SQLite persistent episodic storage + long-term incident/patch semantic graph) so no triage context is lost.
4. **OWASP LLM #1 Prompt Injection & Privacy Protection:** Automatic scrubbing of API keys, AWS secret tokens, PII, and detection of adversarial prompt manipulation or jailbreak payloads before reaching LLM layers.
5. **Multi-Cloud Executable Security Patching:** Automatically generate validated CLI (AWS CLI, Azure CLI, gcloud, kubectl) and IaC (Terraform, K8s YAML) patches paired with verified reverse-action rollback scripts and Human-in-the-Loop (HITL) approval gates.

---

## 3. User Personas
| Persona | Key Need | How CloudSec-RAG Solves It |
|---|---|---|
| **Tier-1 SOC Analyst** | Sifting through thousands of daily SIEM logs without fatigue | Provides 1-second plain-language summaries, threat level ranking, and root-cause explanations. |
| **DevOps / Cloud Engineer** | Fixing misconfigurations fast without breaking production | Provides copy-pasteable, verified CLI/Terraform scripts with rollback plans and blast-radius analysis. |
| **CISO / Head of Security** | Audit compliance (ISO 27001, SOC2, HIPAA, NIST) | Auto-maps each violation to specific compliance controls with an audit trail. |
| **Small Businesses & Startups** | Enterprise security insight without a million-dollar SecOps team | Delivers expert-grade security diagnostics out of the box with zero specialized setup. |
| **Researcher / Student** | Transparent, reproducible, open-source AI security testbed | Modular Python codebase with local/offline execution capability and benchmark datasets. |

---

## 4. In-Scope Features (MVP & Release 1.0)
- **Multi-Cloud Ingestion Engine:** Parsers for AWS CloudTrail, AWS GuardDuty, AWS Config/S3 policies, Azure Activity Logs & NSG rules, GCP Cloud Audit Logs, and Kubernetes manifests (GenKubeSec benchmark).
- **Data Privacy & Secret Redactor:** Ingestion-time sanitization of AWS Access Keys, RSA private keys, JWTs, IPv4/IPv6 private subnets, and user PII.
- **OWASP LLM Injection Guard:** Regex + heuristic classifier to detect prompt injections, instruction bypasses, and delimiter escapes.
- **Hybrid RAG Knowledge Engine:** BM25 + Dense Semantic Vector Retrieval against pre-indexed CIS Cloud Benchmarks (AWS, Azure, GCP, K8s), NIST SP 800-53 controls, and MITRE ATT&CK Cloud Matrix.
- **Anti-Hallucination & NLI Verification Layer:** Post-generation citation verification; cross-verifies command flags against vendor specifications; flags any ungrounded assertions.
- **3-Tier Crash-Resilient Memory System:**
  1. *Working Memory:* Token-bounded conversation buffer.
  2. *Episodic Memory:* ACID SQLite storage for thread persistence.
  3. *Semantic Memory:* Incident knowledge graph with known resolution history.
- **Automated Security Patching & Rollback Generator:** Generates AWS CLI, Azure CLI, GCP gcloud, kubectl commands, and Terraform snippets with paired rollback instructions.
- **Human-in-the-Loop (HITL) Gate:** Interactive approval CLI and Web UI modal preventing automatic execution without verified operator sign-off.
- **Dual Interface:** Interactive Rich Terminal CLI + Production-grade FastAPI REST API with embedded SOC Analyst Web Dashboard.

---

## 5. Out of Scope for MVP
- Live automated execution with root cloud credentials (all patches are generated with dry-run/preview and require HITL approval for safety).
- Real-time packet-level DPI (Deep Packet Inspection); the system focuses on cloud control plane, IAM, storage, network policies, and audit logs.
- Proprietary closed-source hardware appliance requirements.

---

## 6. Success Metrics & Key Performance Indicators (KPIs)
- **Hallucination Rate:** 0.0% ungrounded citations on standard CIS benchmark test suites.
- **Injection Resilience:** >98% detection of OWASP Top 10 LLM adversarial injection prompts.
- **Privacy Hygiene:** 100% redaction of standard AWS credentials (`AKIA...`), bearer tokens, and private keys.
- **Triage Latency:** <1.5s for local analysis / <3.5s for end-to-end RAG reasoning.
- **Rollback Coverage:** 100% of generated patches must include a syntactically valid reverse rollback action.
