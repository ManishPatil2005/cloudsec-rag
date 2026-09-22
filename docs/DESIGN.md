# Design System & UI/UX Guidelines

## Product: CloudSec-RAG
**Focus:** High-trust, clarity-first cybersecurity operations for both seasoned SOC teams and non-expert engineers.

---

## 1. Visual & Communication Philosophy
In cloud security, clarity prevents catastrophic mistakes. Ambiguity or dense jargon leads to alarm fatigue and delayed incident response.
The UI and CLI must adhere to:
1. **Plain-Language First:** Always provide a 2-sentence non-technical explanation before displaying code or CLI flags.
2. **Deterministic Color Coding:**
   - **CRITICAL:** High-contrast Crimson Red (`#EF4444` / ANSI Bold Red)
   - **HIGH:** Bright Amber Orange (`#F97316` / ANSI Yellow)
   - **MEDIUM:** Canary Yellow (`#EAB308`)
   - **LOW / INFORMATIONAL:** Cyber Cyan / Sky Blue (`#0EA5E9`)
   - **VERIFIED GROUNDED / PASS:** Emerald Green (`#10B981`)
3. **Auditability & Traceability:** Citations (e.g., `[CIS-AWS-2.1.5]`) must be visible, with links to control text.
4. **Safety & Blast-Radius Warnings:** Any remediation command that modifies network routing, bucket permissions, or firewall rules must display an amber warning box detailing affected resources.

---

## 2. CLI Interface Design
The CLI uses standard ANSI formatting and structured panels:
```
┌─ [CLOUDSEC-RAG] INCIDENT TRIAGE & REMEDIATION REPORT ──────────────────┐
│ Target Resource: bkt-production-customer-data (AWS ap-south-1)          │
│ Severity: CRITICAL | Grounding Confidence: 99.4% [CIS AWS 2.1.5]        │
├────────────────────────────────────────────────────────────────────────┤
│ 💡 Plain-Language Summary:                                              │
│ "Your storage bucket 'bkt-production-customer-data' has public read    │
│  access enabled without restrictions. Anyone on the internet can list   │
│  and download customer assets without authenticating."                 │
│                                                                        │
│ 🛠️ Executable Remediation (AWS CLI):                                   │
│  $ aws s3api put-public-access-block --bucket bkt-...                  │
│                                                                        │
│ ↩️ Automated Rollback Script:                                          │
│  $ aws s3api delete-public-access-block --bucket bkt-...               │
│                                                                        │
│ 🛡️ Human-in-the-Loop Gate: [A]pprove / [R]eject / [E]xplain            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Web Dashboard Design System
- **Theme:** High-tech Cyber Dark Mode (Slate `#0B0F19`, Dark Surface `#1E293B`, Cyan `#38BDF8`, Emerald `#34D399`, Crimson `#F87171`).
- **Typography:** JetBrains Mono for telemetry, logs, and code; Inter for titles and plain-language executive summaries.
- **Components:**
  - Real-time Alert Feed with multi-cloud icons (AWS, Azure, GCP, K8s).
  - Anti-Hallucination Confidence Gauge (0-100%).
  - One-Click HITL Approval modal with diff visualizer.
  - 3-Tier Memory inspector showing historical incidents and matching past patches.
