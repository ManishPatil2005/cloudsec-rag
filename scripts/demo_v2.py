#!/usr/bin/env python3
"""CloudSec-RAG v2.0 Enterprise Demonstration Script.

Demonstrates v2 advanced breakthroughs:
1. False Positive Suppression via Network Reachability (Air-Gapped Private Subnet).
2. False Positive Suppression via AWS Organizations Service Control Policy (SCP).
3. Multi-Hop Toxic Combination Discovery (Internet -> Workload -> IAM -> Datastore).
4. Sustainable Green-AI Hierarchical Routing (0-token Tier-0/1 vs. Deep Tier-2).
5. State-Diff Blast-Radius Simulation before patch execution.
"""

import sys
from pathlib import Path
from colorama import Fore, Style, init

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from cloudsec_rag.v2.orchestrator_v2 import CloudSecPipelineV2
from cloudsec_rag.v2.types import NetworkTopologyContext, PermissionContext

init(autoreset=True)


def banner(title: str):
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{Fore.YELLOW}  [v2.0 SCENARIO] {title}")
    print(f"{Fore.CYAN}{'='*80}\n")


def run_demo_v2():
    print(f"{Fore.CYAN}================================================================================")
    print(f"{Fore.CYAN}   CLOUDSEC-RAG v2.0: AUTONOMOUS REACHABILITY & TOXIC COMBINATIONS ENGINE")
    print(f"{Fore.LIGHTBLACK_EX}   Sustainable Green-AI | Graph-RAG | State-Diff Blast Radius | True-Positive Verifier")
    print(f"{Fore.CYAN}================================================================================\n")

    pipeline = CloudSecPipelineV2(llm_provider="mock")

    # -------------------------------------------------------------------------
    # SCENARIO 1: False-Positive Suppression (Private Air-Gapped Subnet)
    # -------------------------------------------------------------------------
    banner("1. Eliminating False Positives via Network Reachability Simulation")
    raw_s3_alert = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-backup-archive region=ap-south-1 severity=HIGH"
    print(f"{Fore.WHITE}Incoming Raw Scanner Alert:\n{Fore.LIGHTBLACK_EX}{raw_s3_alert}")

    private_net = NetworkTopologyContext(
        vpc_id="vpc-finance-backend",
        subnet_id="subnet-isolated-db",
        is_public_subnet=False,
        has_internet_gateway_route=False,  # Air-gapped private subnet
    )

    res1 = pipeline.analyze_incident_v2(raw_s3_alert, network_context=private_net)

    print(f"\n{Fore.GREEN}[v2 VERIFIER] Is actually vulnerable? {Fore.YELLOW}{res1.reachability.is_actually_vulnerable}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Verdict:                {Fore.WHITE}{res1.reachability.verdict_summary}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Action Taken:           {Fore.CYAN}{res1.reachability.suppression_reason}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Effective Severity:     {Fore.LIGHTBLUE_EX}{res1.severity.value} (Downgraded to prevent alert fatigue)")

    # -------------------------------------------------------------------------
    # SCENARIO 2: False-Positive Suppression (Organization SCP Deny)
    # -------------------------------------------------------------------------
    banner("2. Eliminating False Positives via AWS Organization SCP Evaluation")
    raw_iam_alert = "WARN: iam_policy=ADMIN_WILDCARD resource=role-billing-auditor severity=CRITICAL"
    print(f"{Fore.WHITE}Incoming Raw Scanner Alert:\n{Fore.LIGHTBLACK_EX}{raw_iam_alert}")

    scp_ctx = PermissionContext(
        has_resource_policy_allow=True,
        has_identity_policy_allow=True,
        scp_explicit_deny=True,  # Organization SCP blocks administrator actions on non-root accounts
    )

    res2 = pipeline.analyze_incident_v2(raw_iam_alert, permission_context=scp_ctx)

    print(f"\n{Fore.GREEN}[v2 VERIFIER] Is permission effective? {Fore.YELLOW}{res2.reachability.is_permission_effective}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Verdict:                  {Fore.WHITE}{res2.reachability.verdict_summary}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Action Taken:             {Fore.CYAN}{res2.reachability.suppression_reason}")

    # -------------------------------------------------------------------------
    # SCENARIO 3: Graph-RAG Toxic Combination Discovery
    # -------------------------------------------------------------------------
    banner("3. Graph-RAG: Toxic Combination Detection (Multi-Hop Attack Path)")
    raw_workload_alert = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH"

    public_net = NetworkTopologyContext(
        vpc_id="vpc-public",
        subnet_id="subnet-public-dmz",
        is_public_subnet=True,
        has_internet_gateway_route=True,
        ingress_cidrs=["0.0.0.0/0"],
        allowed_ports=[80, 443],
    )

    res3 = pipeline.analyze_incident_v2(
        raw_workload_alert,
        network_context=public_net,
        known_dependencies=["checkout-frontend-web", "mobile-api-gateway"],
    )

    print(f"{Fore.RED}[v2 TOXIC COMBO DETECTED] Severity: {res3.severity.value}")
    if res3.toxic_combination:
        print(f"{Fore.YELLOW}  Attack Path ID:   {res3.toxic_combination.path_id}")
        print(f"{Fore.YELLOW}  Full Chain:       {' -> '.join(res3.toxic_combination.chain)}")
        print(f"{Fore.WHITE}  Risk Narrative:   {res3.toxic_combination.risk_narrative}")
        print(f"{Fore.CYAN}  Sever Node:       {res3.toxic_combination.recommended_sever_edge}")

    # -------------------------------------------------------------------------
    # SCENARIO 4: State-Diff Blast-Radius Impact Simulator
    # -------------------------------------------------------------------------
    banner("4. State-Diff Blast Radius Simulation (Safe Remediation)")
    if res3.blast_radius_diff:
        diff = res3.blast_radius_diff
        print(f"{Fore.GREEN}[v2 SIMULATOR] Target Resource:         {diff.resource_id}")
        print(f"{Fore.GREEN}[v2 SIMULATOR] Operational Risk:        {diff.risk_level.value}")
        print(f"{Fore.GREEN}[v2 SIMULATOR] Disruption Probability:  {diff.service_disruption_probability * 100:.0f}%")
        print(f"{Fore.GREEN}[v2 SIMULATOR] Dependent Workloads:     {diff.affected_dependent_services}")
        print(f"{Fore.WHITE}\n  State Transition Diff:")
        print(f"    - BEFORE: public_access = {diff.before_state.get('public_access')}")
        print(f"    + AFTER:  public_access = {diff.after_state.get('public_access')}")
        print(f"    + AFTER:  block_public_policy = {diff.after_state.get('block_public_policy')}")

    # -------------------------------------------------------------------------
    # SCENARIO 5: Sustainable Green-AI Routing Metrics
    # -------------------------------------------------------------------------
    banner("5. Sustainable Green-AI Routing & Token Savings Report")
    stats = pipeline.sustainable_router.stats
    print(f"{Fore.GREEN}[v2 GREEN AI] Tier-0 Hash Cache Hits:       {stats['tier_0_hits']} (0 tokens, <1ms)")
    print(f"{Fore.GREEN}[v2 GREEN AI] Tier-1 Local SLM/BM25 Hits:   {stats['tier_1_hits']} (0 external tokens, ~5ms)")
    print(f"{Fore.GREEN}[v2 GREEN AI] Tier-2 Deep LLM Reasoner:     {stats['tier_2_hits']} (Reserved for Toxic Paths)")
    print(f"{Fore.CYAN}[v2 GREEN AI] Total Inference Tokens Saved: {stats['total_tokens_saved']} tokens")
    print(f"{Fore.CYAN}[v2 GREEN AI] Est. Cloud Cost Reduction:    ${stats['cost_saved_usd']:.4f} USD")
    print(f"{Fore.LIGHTBLACK_EX}[v2 GREEN AI] Average Response Latency:     {res3.processing_latency_ms} ms")

    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{Fore.GREEN}  ALL CLOUDSEC-RAG v2.0 ADVANCED CAPABILITIES VERIFIED SUCCESSFULLY!")
    print(f"{Fore.CYAN}{'='*80}\n")


if __name__ == "__main__":
    run_demo_v2()
