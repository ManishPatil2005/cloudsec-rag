"""Curated Knowledge Base of CIS Benchmarks, NIST SP 800-53, and MITRE ATT&CK Cloud Controls.

Provides ground truth for anti-hallucination verification and deterministic remediation fallbacks.
"""

from typing import List
from ..core.types import BenchmarkReference


def get_default_benchmarks() -> List[BenchmarkReference]:
    """Returns curated authoritative security benchmark rules covering AWS, Azure, GCP, and Kubernetes."""
    return [
        BenchmarkReference(
            citation_id="CIS-AWS-2.1.5",
            framework="CIS_AWS_BENCHMARK_v3.0",
            title="Ensure S3 Bucket Policy Does Not Allow Public Read/Write Access",
            description="Amazon S3 buckets should prohibit public read or write access via bucket policies or ACLs to prevent unauthorized internet-wide data exfiltration.",
            rationale="Permissive bucket policies expose sensitive customer records, backups, and proprietary source code directly to the internet.",
            impact="Public read allows anyone to download objects. Public write permits adversaries to overwrite objects or upload malicious payloads.",
            remediation_command="aws s3api put-public-access-block --bucket {RESOURCE_ID} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            rollback_command="aws s3api delete-public-access-block --bucket {RESOURCE_ID}",
            iac_template="""resource "aws_s3_bucket_public_access_block" "remediation" {
  bucket                  = "{RESOURCE_ID}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        ),
        BenchmarkReference(
            citation_id="CIS-AWS-1.16",
            framework="CIS_AWS_BENCHMARK_v3.0",
            title="Ensure IAM Policies Do Not Have Full Administrative Privileges (*:*)",
            description="IAM policies should enforce the Principle of Least Privilege and avoid granting wildcard Action '*' on Resource '*'.",
            rationale="Overly permissive IAM roles can be assumed by compromised workloads to achieve complete AWS account takeover.",
            impact="Adversary can create backdoor credentials, delete audit logs, and deploy unauthorized cryptominers.",
            remediation_command="aws iam detach-role-policy --role-name {RESOURCE_ID} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess && aws iam attach-role-policy --role-name {RESOURCE_ID} --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
            rollback_command="aws iam attach-role-policy --role-name {RESOURCE_ID} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            iac_template="""resource "aws_iam_role_policy_attachment" "least_privilege" {
  role       = "{RESOURCE_ID}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}""",
        ),
        BenchmarkReference(
            citation_id="CIS-AWS-4.1",
            framework="CIS_AWS_BENCHMARK_v3.0",
            title="Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to Port 22 (SSH)",
            description="AWS EC2 security groups and AuthorizeSecurityGroupIngress rules should not allow unrestricted internet access (0.0.0.0/0) to TCP Port 22 or management ports.",
            rationale="Publicly exposed SSH endpoints in EC2 security groups are subjected to automated brute-force attacks and credential stuffing within minutes of deployment.",
            impact="Unauthorized remote shell access to EC2 compute instances and lateral cloud movement.",
            remediation_command="aws ec2 revoke-security-group-ingress --group-id {RESOURCE_ID} --protocol tcp --port 22 --cidr 0.0.0.0/0",
            rollback_command="aws ec2 authorize-security-group-ingress --group-id {RESOURCE_ID} --protocol tcp --port 22 --cidr 0.0.0.0/0",
            iac_template="""resource "aws_security_group_rule" "remove_public_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"] # Restricted corporate subnet
  security_group_id = "{RESOURCE_ID}"
}""",
        ),
        BenchmarkReference(
            citation_id="CIS-AZURE-6.1",
            framework="CIS_AZURE_BENCHMARK_v2.0",
            title="Ensure Network Security Group Rule Restricts Inbound RDP (Port 3389)",
            description="Azure Network Security Groups (NSGs) must not allow inbound traffic from internet '*' or '0.0.0.0/0' to port 3389.",
            rationale="Exposed Windows Remote Desktop Protocol (RDP) ports are the primary vector for enterprise ransomware deployment.",
            impact="Adversaries gain interactive graphical remote desktop access.",
            remediation_command="az network nsg rule delete --resource-group {RESOURCE_GROUP} --nsg-name {RESOURCE_ID} --name Allow-RDP-Internet",
            rollback_command="az network nsg rule create --resource-group {RESOURCE_GROUP} --nsg-name {RESOURCE_ID} --name Allow-RDP-Internet --priority 1000 --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 3389",
            iac_template="""resource "azurerm_network_security_rule" "block_rdp" {
  name                        = "Deny-Internet-RDP"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "3389"
  source_address_prefix      = "Internet"
  destination_address_prefix = "*"
  resource_group_name         = "{RESOURCE_GROUP}"
  network_security_group_name = "{RESOURCE_ID}"
}""",
        ),
        BenchmarkReference(
            citation_id="CIS-GCP-5.1",
            framework="CIS_GCP_BENCHMARK_v3.0",
            title="Ensure Cloud Storage Buckets Are Not Publicly Accessible to allUsers",
            description="Google Cloud Storage buckets must enforce uniform bucket-level access and remove allUsers and allAuthenticatedUsers from IAM bindings.",
            rationale="Public bucket IAM bindings bypass project-level identity access checks, exposing data globally.",
            impact="Unauthorized worldwide reading or tampering of Google Cloud Storage objects.",
            remediation_command="gcloud storage buckets remove-iam-policy-binding gs://{RESOURCE_ID} --member=allUsers --role=roles/storage.objectViewer && gcloud storage buckets update gs://{RESOURCE_ID} --uniform-bucket-level-access",
            rollback_command="gcloud storage buckets add-iam-policy-binding gs://{RESOURCE_ID} --member=allUsers --role=roles/storage.objectViewer",
            iac_template="""resource "google_storage_bucket" "secure_bucket" {
  name                        = "{RESOURCE_ID}"
  uniform_bucket_level_access = true
}""",
        ),
        BenchmarkReference(
            citation_id="CIS-K8S-5.2.1",
            framework="CIS_KUBERNETES_BENCHMARK_v1.8",
            title="Minimize the Admission of Privileged Containers",
            description="Privileged containers inherit all root Linux capabilities from the host node, negating container boundary isolation.",
            rationale="A container escape vulnerability in a privileged container immediately grants root access over the underlying Kubernetes worker node.",
            impact="Adversary can inspect node host files, sniff container-to-container network traffic, and compromise all other workloads on the node.",
            remediation_command="kubectl patch deployment {RESOURCE_ID} -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"app\",\"securityContext\":{\"privileged\":false,\"allowPrivilegeEscalation\":false,\"readOnlyRootFilesystem\":true}}]}}}}'",
            rollback_command="kubectl patch deployment {RESOURCE_ID} -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"app\",\"securityContext\":{\"privileged\":true}}]}}}}'",
            iac_template="""securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true""",
        ),
        BenchmarkReference(
            citation_id="NIST-AC-3",
            framework="NIST_SP_800_53_R5",
            title="Access Enforcement across Cloud Management Boundaries",
            description="The system must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
            rationale="Uncontrolled access leads to lateral movement and unauthorized privilege escalation.",
            impact="Breach of confidentiality and data integrity across multi-tenant cloud planes.",
            remediation_command="# Apply strict RBAC policy and enable MFA requirement\naws iam update-account-password-policy --require-numbers --require-symbols --minimum-password-length 14",
            rollback_command="# Restore standard password policy\naws iam delete-account-password-policy",
            iac_template="""# NIST AC-3 Compliance Baseline
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = 14
  require_symbols        = true
  require_numbers        = true
}""",
        ),
        BenchmarkReference(
            citation_id="MITRE-ATTACK-T1530",
            framework="MITRE_ATTACK_CLOUD",
            title="Data from Cloud Storage Object Exfiltration",
            description="Adversaries may access data objects from cloud storage (e.g., AWS S3, GCP Cloud Storage, Azure Blob Storage) that have been improperly secured.",
            rationale="Adversaries systematically crawl cloud object APIs searching for unsecured buckets without authentication.",
            impact="Mass exfiltration of corporate intellectual property, credentials, and databases.",
            remediation_command="aws s3api put-bucket-encryption --bucket {RESOURCE_ID} --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
            rollback_command="aws s3api delete-bucket-encryption --bucket {RESOURCE_ID}",
            iac_template="""resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = "{RESOURCE_ID}"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}""",
        )
    ]
