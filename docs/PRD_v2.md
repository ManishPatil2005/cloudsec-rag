# Product Requirements Document (PRD) — Version 2.0

## Product: CloudSec-RAG v2.0 (Autonomous Cloud SecOps & Reachability Verification Engine)
**Version:** 2.0.0-PROD  
**Author:** Manish Pundlik Patil (Ref: B.Tech CSE Semester Project, NLP)  
**Target:** Enterprise SecOps, Cloud Platform Engineers, Autonomous SOCs at Cloud Scale  

---

## 1. Problem Statement & Motivation for v2
While CloudSec-RAG v1.0 successfully delivered zero-hallucination grounded RAG, 3-tier persistent memory, and automated patching, real-world deployment across enterprise environments revealed three major operational bottlenecks:

1. **Context Blindness & False-Positive Alert Fatigue:**  
   Security scanners flag resources based on isolated configuration attributes (e.g., an S3 bucket with `PUBLIC_READ` policy). However, in production:
   - An AWS Organization **Service Control Policy (SCP)** may explicitly deny public S3 access across the entire organizational unit (OU).
   - The resource may reside in an **isolated private subnet** with no Internet Gateway route.
   - The resource may be completely unattached or empty.  
   *Result:* SecOps teams waste up to **60% of their operational hours** investigating theoretical alerts that are not actually exploitable.

2. **Graph-Blindness (Toxic Combinations):**  
   Modern cloud attacks do not rely on a single critical misconfiguration. Instead, adversaries chain multiple seemingly benign or "LOW" severity flaws together:
   - A public-facing web pod with IMDSv1 enabled (Medium) + an overprivileged EC2 instance role (Low) + an internal datastore with unencrypted backups (Low) = **CRITICAL Complete Account Takeover & Data Breach**.  
   *Result:* Static single-alert triage misses multi-hop toxic attack paths.

3. **Compute & Token Inefficiency (Unsustainable AI):**  
   Invoking multi-billion parameter LLMs for every repetitive log line is economically infeasible, introduces latency spikes, and generates an unnecessary carbon footprint.  
   *Result:* Real-time cloud operations require a tiered, sustainable inference routing strategy.

4. **Blast-Radius Blindness in Automated Patching:**  
   Applying a remediation patch (e.g., blocking public access or revoking an IAM policy) without knowing which active microservices depend on that resource can trigger catastrophic enterprise outages.

---

## 2. Core Objectives of v2.0
1. **Automated Exploitability & Reachability Verification:**  
   Before alarming operators or generating patches, simulate network routing and effective IAM permissions to confirm whether the detected vulnerability is **actually reachable and exploitable** from untrusted boundaries. Suppress benign false positives automatically.
2. **Multi-Cloud Asset & Identity Graph (Graph-RAG):**  
   Model cloud infrastructure as an interconnected directed topology graph (VPCs, Subnets, Gateways, Compute, IAM Identities, Datastores) to detect **Toxic Combinations**.
3. **Sustainable Tiered Inference (Green Computing):**  
   Introduce a 3-tier routing architecture:
   - *Tier-0 (0 Tokens, <1ms):* Deterministic pattern and hash cache.
   - *Tier-1 (Local Compute, ~5ms):* Subword embedding & local vector scoring.
   - *Tier-2 (Deep LLM):* Invoked only when toxic combinations or ambiguous multi-hop attack paths exist. Saves **>80% token costs and inference latency**.
4. **Real-Time Asynchronous Streaming Engine:**  
   Event-driven streaming worker pool supporting high-throughput telemetry ingestion (AWS EventBridge, Azure Event Hubs, K8s Admission Webhooks) with non-blocking async micro-batching.
5. **State-Diff Blast-Radius Impact Simulator:**  
   Before executing or approving any patch, compute the exact dependent services, active connections, and workloads that will be impacted by the configuration drift.

---

## 3. Success Metrics for v2.0
* **False-Positive Reduction:** >75% reduction in operator alert volume by suppressing unreachable/blocked misconfigurations.
* **Toxic Combination Detection Rate:** 100% discovery of multi-hop paths chaining internet exposure to sensitive datastores.
* **Inference Efficiency:** >80% reduction in external LLM token usage via sustainable Tier-0/1 routing.
* **Real-Time Throughput:** Support for concurrent streaming events with sub-25ms average triage latency for Tier-0/1.
* **Remediation Safety:** 100% of generated patches include state-diff blast radius analysis and verified inverse rollbacks.
