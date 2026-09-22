"""Command Line Interface for CloudSec-RAG.

Interactive terminal triage, plain-language translation, and Human-in-the-Loop patch approval.
"""

import sys
from typing import Optional
import click
from colorama import Fore, Style, init

from .core.exceptions import PromptInjectionAttemptError
from .pipeline.orchestrator import CloudSecPipeline

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.CYAN}========================================================================
   ____ _                 _____                 ____      _    ____ 
  / ___| | ___  _   _  __| / ___|  ___  ___    |  _ \\    / \\  / ___|
 | |   | |/ _ \\| | | |/ _` \\___ \\ / _ \\/ __|---| |_) |  / _ \\| |  _ 
 | |___| | (_) | |_| | (_| |___) |  __/ (__|---|  _ <  / ___ \\ |_| |
  \\____|_|\\___/ \\__,_|\\__,_|____/ \\___|\\___|   |_| \\_\\/_/   \\_\\____|
{Fore.LIGHTBLACK_EX}  Enterprise Multi-Cloud AI Security & Anti-Hallucination Patching Engine
{Fore.CYAN}========================================================================
"""
    print(banner)


@click.group()
def cli():
    """CloudSec-RAG: Grounded AI Cloud Security & Remediation CLI."""
    pass


@cli.command("analyze")
@click.option("--log", "-l", help="Direct raw cloud log string to analyze")
@click.option("--file", "-f", type=click.Path(exists=True), help="File path containing raw JSON, YAML, or text alert")
@click.option("--provider", "-p", default=None, help="Cloud provider hint (AWS, AZURE, GCP, KUBERNETES)")
@click.option("--interactive/--no-interactive", default=True, help="Enable interactive Human-in-the-Loop patch review")
def analyze(log: Optional[str], file: Optional[str], provider: Optional[str], interactive: bool):
    """Analyze a cloud security alert, explain in plain language, and generate verified patches."""
    print_banner()

    content = ""
    if file:
        with open(file, "r", encoding="utf-8") as fp:
            content = fp.read()
    elif log:
        content = log
    else:
        # Default sample scenario from presentation PDF:
        content = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH code=CFG-0091"
        print(f"{Fore.YELLOW}[*] No input provided. Using sample S3 public read alert from study presentation.\n")

    print(f"{Fore.BLUE}[*] Initializing Grounded Pipeline...")
    pipeline = CloudSecPipeline()

    try:
        print(f"{Fore.BLUE}[*] Sanitizing secrets and scanning for adversarial prompt injections...")
        analysis = pipeline.analyze_incident(content, provider_hint=provider)
    except PromptInjectionAttemptError as e:
        print(f"\n{Fore.RED}[!] ADVERSARIAL ATTACK BLOCKED (OWASP LLM #1 Prompt Injection)!")
        print(f"{Fore.RED}    Pattern matched: {e.pattern}")
        print(f"{Fore.RED}    Incident flagged and quarantined in security memory.\n")
        sys.exit(1)

    # Display Clean Output
    print(f"\n{Fore.GREEN}[+] ANALYSIS COMPLETE -- GROUNDED & FACTUALLY VERIFIED")
    print(f"{Fore.WHITE}{'='*72}")
    print(f"{Fore.YELLOW}Risk Title:    {Fore.WHITE}{analysis.risk_title}")
    print(f"{Fore.YELLOW}Target:        {Fore.WHITE}{analysis.resource_id} ({analysis.provider.value})")
    
    sev_color = Fore.RED if analysis.severity.value in ["CRITICAL", "HIGH"] else Fore.YELLOW
    print(f"{Fore.YELLOW}Severity:      {sev_color}{analysis.severity.value}")
    print(f"{Fore.YELLOW}Confidence:    {Fore.GREEN}{analysis.grounding_confidence * 100:.1f}% "
          f"{'(Deterministic CIS Baseline)' if analysis.is_deterministic_fallback else '(LLM Grounded)'}")
    print(f"{Fore.WHITE}{'-'*72}")

    print(f"\n{Fore.CYAN}[i] PLAIN-LANGUAGE EXPLANATION (FOR DEVOPS / NON-EXPERTS):")
    print(f"{Fore.WHITE}{analysis.plain_language_summary}\n")

    print(f"\n{Fore.CYAN}[*] ROOT CAUSE & TECHNICAL BREAKDOWN:")
    print(f"{Fore.LIGHTBLACK_EX}{analysis.technical_breakdown}\n")

    print(f"\n{Fore.CYAN}[#] VERIFIED BENCHMARK CITATIONS:")
    for cit in analysis.verified_citations:
        print(f"  * {Fore.GREEN}[{cit.citation_id}]{Fore.WHITE} {cit.title} ({cit.framework})")

    if analysis.executable_patch:
        print(f"\n{Fore.GREEN}[PATCH] EXECUTABLE SECURITY PATCH ({analysis.executable_patch.patch_type.value}):")
        print(f"{Fore.LIGHTGREEN_EX}{analysis.executable_patch.command}")

        if analysis.executable_patch.iac_code:
            print(f"\n{Fore.GREEN}[IaC] INFRASTRUCTURE-AS-CODE (IaC) SNIPPET:")
            print(f"{Fore.LIGHTBLACK_EX}{analysis.executable_patch.iac_code}")

    if analysis.rollback_plan:
        print(f"\n{Fore.MAGENTA}[ROLLBACK] AUTOMATED INVERSE ROLLBACK PLAN:")
        print(f"{Fore.LIGHTMAGENTA_EX}{analysis.rollback_plan.command}")
        print(f"{Fore.LIGHTBLACK_EX}Safety Note: {analysis.rollback_plan.safety_instructions}")

    print(f"\n{Fore.WHITE}{'='*72}")

    # Human-in-the-Loop review
    if interactive and analysis.executable_patch:
        print(f"\n{Fore.YELLOW}[HITL] HUMAN-IN-THE-LOOP APPROVAL GATE")
        decision = click.prompt(
            f"{Fore.WHITE}Approve this patch for execution? [A]pprove / [R]eject",
            default="A",
            show_default=True,
        )

        hitl_decision = pipeline.hitl_gate.review_patch(
            incident_id=analysis.incident_id,
            patch=analysis.executable_patch,
            decision_str="APPROVED" if decision.strip().upper() == "A" else "REJECTED",
            operator_id="sec-analyst-01",
        )
        pipeline.sqlite_store.save_hitl_decision(hitl_decision)

        if hitl_decision.decision == "APPROVED":
            print(f"{Fore.GREEN}[OK] Patch APPROVED and signed off by operator. Audit logged to persistent SQLite memory.")
        else:
            print(f"{Fore.RED}[REJECTED] Patch REJECTED by operator. Remediation aborted.")


@cli.command("serve")
@click.option("--port", "-p", default=8000, help="Port to bind API server")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind API server")
def serve(port: int, host: str):
    """Start the FastAPI backend and Cyber SOC Dashboard."""
    import uvicorn
    print_banner()
    print(f"{Fore.GREEN}[*] Launching CloudSec-RAG Server on http://{host}:{port}")
    uvicorn.run("cloudsec_rag.api.server:app", host=host, port=port, reload=False)


@cli.command("analyze-v2")
@click.option("--log", "-l", help="Direct raw cloud log string to analyze")
@click.option("--file", "-f", type=click.Path(exists=True), help="File path containing raw JSON, YAML, or text alert")
@click.option("--public-subnet/--private-subnet", default=True, help="Simulate public vs. private air-gapped subnet")
@click.option("--scp-deny/--no-scp-deny", default=False, help="Simulate AWS Organization SCP explicit deny")
@click.option("--deps", default="", help="Comma-separated dependent services (e.g. 'cdn,payment-api')")
def analyze_v2(log: Optional[str], file: Optional[str], public_subnet: bool, scp_deny: bool, deps: str):
    """v2.0 Autonomous Analysis with Reachability Verification, Graph-RAG, and Blast-Radius Simulation."""
    from .v2.orchestrator_v2 import CloudSecPipelineV2
    from .v2.types import NetworkTopologyContext, PermissionContext

    print_banner()
    print(f"{Fore.CYAN}--- CLOUDSEC-RAG v2.0 AUTONOMOUS REACHABILITY & GRAPH ENGINE ---\n")

    content = ""
    if file:
        with open(file, "r", encoding="utf-8") as fp:
            content = fp.read()
    elif log:
        content = log
    else:
        content = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH code=CFG-0091"
        print(f"{Fore.YELLOW}[*] Using default sample alert from study presentation.\n")

    net_ctx = NetworkTopologyContext(
        vpc_id="vpc-prod",
        subnet_id="subnet-dmz" if public_subnet else "subnet-isolated",
        is_public_subnet=public_subnet,
        has_internet_gateway_route=public_subnet,
        ingress_cidrs=["0.0.0.0/0"] if public_subnet else ["10.0.0.0/16"],
    )

    perm_ctx = PermissionContext(
        has_resource_policy_allow=True,
        has_identity_policy_allow=True,
        scp_explicit_deny=scp_deny,
    )

    dep_list = [d.strip() for d in deps.split(",") if d.strip()]

    pipeline_v2 = CloudSecPipelineV2()
    res = pipeline_v2.analyze_incident_v2(
        content,
        network_context=net_ctx,
        permission_context=perm_ctx,
        known_dependencies=dep_list,
    )

    print(f"{Fore.GREEN}[v2 VERIFIER] Is actually vulnerable? {Fore.YELLOW}{res.reachability.is_actually_vulnerable}")
    print(f"{Fore.GREEN}[v2 VERIFIER] Reachability Verdict:    {Fore.WHITE}{res.reachability.verdict_summary}")
    if res.reachability.suppression_reason:
        print(f"{Fore.CYAN}[v2 VERIFIER] False-Positive Status:   {Fore.LIGHTCYAN_EX}{res.reachability.suppression_reason}")

    print(f"\n{Fore.YELLOW}Effective Severity:  {Fore.RED if res.severity.value in ['CRITICAL', 'HIGH'] else Fore.CYAN}{res.severity.value}")
    print(f"{Fore.YELLOW}Routing Tier Used:   {Fore.GREEN}{res.sustainable_tier_used.value} ({res.tokens_consumed} tokens consumed)")
    print(f"{Fore.YELLOW}Processing Latency:  {Fore.GREEN}{res.processing_latency_ms} ms")

    if res.toxic_combination:
        print(f"\n{Fore.RED}[!] TOXIC ATTACK PATH DETECTED:")
        print(f"{Fore.WHITE}    Chain: {' -> '.join(res.toxic_combination.chain)}")
        print(f"{Fore.YELLOW}    {res.toxic_combination.risk_narrative}")

    print(f"\n{Fore.CYAN}[i] Plain-Language Explanation:")
    print(f"{Fore.WHITE}{res.plain_language_summary}\n")

    if res.executable_patch:
        print(f"{Fore.GREEN}[PATCH] Executable Remediation ({res.executable_patch.patch_type.value}):")
        print(f"{Fore.LIGHTGREEN_EX}{res.executable_patch.command}\n")

    if res.blast_radius_diff:
        print(f"{Fore.MAGENTA}[SIMULATOR] Blast Radius Risk: {res.blast_radius_diff.risk_level.value}")
        print(f"{Fore.WHITE}    Disruption Probability: {res.blast_radius_diff.service_disruption_probability * 100:.0f}%")
        print(f"{Fore.WHITE}    {res.blast_radius_diff.summary}\n")

