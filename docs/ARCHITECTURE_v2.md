# System Architecture Document — Version 2.0

## Product: CloudSec-RAG v2.0
**Architecture:** Autonomous Graph-RAG, Real-Time Streaming, Reachability Verification & Sustainable Tiered Inference Engine  

---

## 1. High-Level v2.0 Architecture Diagram

```mermaid
flowchart TD
    subgraph STREAMING["1. Real-Time Streaming Ingestion Engine"]
        E1["Telemetry Streams<br/>(AWS EventBridge, Azure Monitor, K8s Audits)"] --> E2["Async Event Queue & Micro-Batcher"]
        E2 --> E3["Privacy Scrubber v2<br/>(Secret & PII Redactor)"]
        E3 --> E4["OWASP Injection Filter"]
    end

    subgraph GRAPH_ENGINE["2. Cloud Topology & Graph-RAG Engine"]
        G1[("Multi-Cloud Asset & Identity Graph<br/>(VPCs, Subnets, Gateways, IAM, Pods, Buckets)")]
        G2["Graph Traversal & Attack Path Engine"]
        G1 <--> G2
    end

    subgraph VERIFIER["3. Exploitability & Reachability Verifier (Anti-False-Positive)"]
        V1["Network Reachability Analyzer<br/>(IGW, Route Tables, CIDR, Ingress Rules)"]
        V2["Effective Permission Engine<br/>(IAM Policies + SCPs + Permission Boundaries)"]
        V3["Toxic Combination Evaluator<br/>(Chains Minor Flaws ➔ Critical Breaches)"]
        V1 & V2 & V3 --> V4{"Is Actually Exploitable?"}
        V4 -- "NO: Blocked by SCP or Air-Gapped" --> V5["Auto-Suppressed as Benign<br/>(Zero Alert Fatigue)"]
        V4 -- "YES: Verified Reachable Exposure" --> V6["Confirmed Active Threat"]
    end

    subgraph SUSTAINABLE_ROUTER["4. Sustainable Green-AI Hierarchical Router"]
        R1{"Tier-0: Hash/Signature Cache<br/>(0 Tokens, <1ms)"}
        R2{"Tier-1: Local Fast Embedder & BM25<br/>(0 LLM Tokens, ~5ms)"}
        R3["Tier-2: Deep Grounded LLM Reasoner<br/>(Only Complex / Novel Toxic Paths)"]
        V6 --> R1
        R1 -- "Cache Miss" --> R2
        R2 -- "Novel / Multi-Hop Topology" --> R3
    end

    subgraph BLAST_SIM["5. State-Diff Blast-Radius Simulator & HITL v2"]
        B1["State-Diff Dependency Analyzer<br/>(Calculates Interrupted Workloads)"]
        B2["Canary Patch Dry-Run Validator"]
        B3["Human-in-the-Loop Sign-off & Inverse Rollback"]
        B1 --> B2 --> B3
    end

    subgraph PERSISTENCE["6. 3-Tier Resilient Memory"]
        M1["Tier-1: Working Session Buffer"]
        M2[("Tier-2: ACID SQLite Event Store")]
        M3[("Tier-3: Semantic Attack Path Graph")]
    end

    STREAMING --> GRAPH_ENGINE
    GRAPH_ENGINE --> VERIFIER
    SUSTAINABLE_ROUTER --> BLAST_SIM
    BLAST_SIM <--> PERSISTENCE
```

---

## 2. Core Subsystems

### 2.1 Exploitability & Reachability Verifier (`cloudsec_rag.v2.verifier`)
Traditional CSPM tools raise alerts based on isolated policy text. v2 verifies whether an adversary can actually access or abuse the asset:
1. **Network Reachability Evaluation:**
   $$\text{IsReachable} = \text{HasInternetGateway}(\text{VPC}) \land \text{RouteToIGW}(\text{Subnet}) \land \text{SecurityGroupAllows}(\text{0.0.0.0/0}, \text{Port})$$
   If the resource is in an air-gapped VPC or internal subnet with only private NAT egress, direct inbound exposure is **disproven**.
2. **Effective Permission Simulation:**
   $$\text{EffectiveAccess} = (\text{ResourcePolicy} \lor \text{IdentityPolicy}) \land \neg \text{ExplicitDeny} \land \neg \text{SCP\_Deny} \land \text{PermissionBoundary}$$
   If an AWS Organization Service Control Policy (SCP) enforces `Deny` on public S3 operations, the bucket is mathematically protected. v2 downgrades or suppresses the finding, eliminating false positives.

### 2.2 Cloud Topology & Toxic Combinations (`cloudsec_rag.v2.graph`)
Models assets as nodes and relationships as edges:
- `InternetGateway` $\xrightarrow{\text{routes\_to}}$ `Subnet` $\xrightarrow{\text{hosts}}$ `Workload` $\xrightarrow{\text{assumes}}$ `IAMRole` $\xrightarrow{\text{reads}}$ `Datastore`
- **Toxic Combination Detection:** An alert with individual severity `LOW` (e.g. EC2 instance profile has read access to an S3 bucket) combined with another `LOW` alert (EC2 instance runs an unpatched web service with port 80 open) escalates into a **CRITICAL Toxic Attack Path** because the chain permits internet-to-datastore exfiltration.

### 2.3 Sustainable Green-AI Routing (`cloudsec_rag.v2.router`)
Instead of dispatching massive LLM calls for every event:
- **Tier-0 (0 Tokens):** Exact hash lookup of known remediations in SQLite/cache (<1ms).
- **Tier-1 (0 LLM Tokens):** Local BM25 + dense semantic subword similarity against CIS benchmark controls (~5ms).
- **Tier-2 (LLM Reasoning):** Only invoked for unmapped, high-ambiguity, or complex toxic combinations.
*Result:* **>80% reduction in token consumption and operating costs.**

### 2.4 State-Diff Blast-Radius Simulator (`cloudsec_rag.v2.simulation`)
Before a patch is executed, the simulator maps:
- **Direct Impact:** The configuration keys being modified.
- **Collateral Impact:** Which microservices, Lambda functions, or external partners currently authenticate or connect to this resource.
- Generates a visual before/after state diff.

### 2.5 Real-Time Event-Driven Streaming Engine (`cloudsec_rag.v2.streaming`)
- Python `asyncio` event queue and consumer worker pools.
- Backpressure control and sliding window micro-batching.
- Capable of streaming real-time alerts from AWS EventBridge, Azure Event Hub, or Kubernetes Admission Webhooks.
