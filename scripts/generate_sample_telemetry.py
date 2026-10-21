#!/usr/bin/env python3
"""Generate realistic multi-cloud telemetry dataset (100 logs).

Includes:
- 90 Benign / Normal Operational Logs (AWS, Azure, GCP, K8s)
- 5 Vulnerable Logs (Security Misconfigurations / CIS compliance violations)
- 5 Dangerous Logs (Active Adversary / Toxic Combinations / Privilege Escalation)
"""

import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

base_time = datetime(2026, 10, 21, 6, 0, 0, tzinfo=timezone.utc)

def ts(offset_minutes: int) -> str:
    return (base_time + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

records = []

# ==============================================================================
# 5 VULNERABLE LOGS (Misconfigurations / CIS & NIST Compliance Failures)
# ==============================================================================

vulnerable_logs = [
    {
        "_meta": {
            "id": "VULN-001",
            "category": "VULNERABLE",
            "threat_label": "S3 Public Read/Write Wildcard Policy",
            "mitre_technique": "T1530 - Data from Cloud Storage Object",
            "benchmark_violation": "CIS-AWS-2.1.5 / NIST-AC-3"
        },
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJQABLZS5A3YEXAMPLE",
            "arn": "arn:aws:iam::112233445566:user/devops-intern",
            "accountId": "112233445566",
            "userName": "devops-intern"
        },
        "eventTime": ts(5),
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.23",
        "userAgent": "aws-cli/2.15.15 Python/3.11.8",
        "requestParameters": {
            "bucketName": "corp-prod-financial-vault",
            "bucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicAccessForTesting",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": "arn:aws:s3:::corp-prod-financial-vault/*"
                    }
                ]
            }
        },
        "responseElements": None,
        "readOnly": False,
        "eventType": "AwsApiCall"
    },
    {
        "_meta": {
            "id": "VULN-002",
            "category": "VULNERABLE",
            "threat_label": "Security Group Open Ingress SSH (0.0.0.0/0)",
            "mitre_technique": "T1046 - Network Service Discovery",
            "benchmark_violation": "CIS-AWS-5.2 / NIST-SC-7"
        },
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAJQABLZS5A3YEXAMPLE:contractor-session",
            "arn": "arn:aws:iam::112233445566:role/ContractorDevRole",
            "accountId": "112233445566"
        },
        "eventTime": ts(12),
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "203.0.113.45",
        "requestParameters": {
            "groupId": "sg-01a9f02bca882194d",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0", "description": "Temporary SSH for debugging"}]}
                    }
                ]
            }
        },
        "responseElements": {"_return": True},
        "readOnly": False,
        "eventType": "AwsApiCall"
    },
    {
        "_meta": {
            "id": "VULN-003",
            "category": "VULNERABLE",
            "threat_label": "Azure NSG Ingress Rule Exposing RDP to Internet",
            "mitre_technique": "T1021.001 - Remote Services: Remote Desktop Protocol",
            "benchmark_violation": "CIS-Azure-6.2 / NIST-SC-7"
        },
        "time": ts(18),
        "resourceId": "/subscriptions/sub-8491-prod/resourceGroups/rg-core-infra/providers/Microsoft.Network/networkSecurityGroups/nsg-db-backend/securityRules/AllowRDPGlobal",
        "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
        "category": "Administrative",
        "resultType": "Success",
        "caller": "admin-contractor@enterprise.onmicrosoft.com",
        "properties": {
            "requestbody": {
                "properties": {
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "destinationPortRange": "3389",
                    "direction": "Inbound",
                    "priority": 110
                }
            }
        }
    },
    {
        "_meta": {
            "id": "VULN-004",
            "category": "VULNERABLE",
            "threat_label": "GCP Cloud Storage Bucket Public Exposure (allUsers)",
            "mitre_technique": "T1530 - Data from Cloud Storage Object",
            "benchmark_violation": "CIS-GCP-5.1 / NIST-AC-3"
        },
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.setIamPermissions",
            "resourceName": "projects/_/buckets/gcp-corp-internal-backups",
            "authenticationInfo": {"principalEmail": "automation-worker@project-prod-9921.iam.gserviceaccount.com"},
            "serviceData": {
                "policyDelta": {
                    "bindingDeltas": [
                        {
                            "action": "ADD",
                            "role": "roles/storage.objectViewer",
                            "member": "allUsers"
                        }
                    ]
                }
            }
        },
        "timestamp": ts(24),
        "severity": "NOTICE",
        "logName": "projects/project-prod-9921/logs/cloudaudit.googleapis.com%2Factivity"
    },
    {
        "_meta": {
            "id": "VULN-005",
            "category": "VULNERABLE",
            "threat_label": "Kubernetes Privileged Container Deployment (root hostPID)",
            "mitre_technique": "T1611 - Escape to Host",
            "benchmark_violation": "CIS-K8s-5.2.1 / NIST-AC-6"
        },
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": "k8s-audit-b2910fa-4029",
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/namespaces/production/pods",
        "verb": "create",
        "user": {"username": "developer-service-account", "groups": ["system:serviceaccounts", "system:authenticated"]},
        "sourceIPs": ["10.244.2.15"],
        "objectRef": {"resource": "pods", "namespace": "production", "name": "maintenance-task-pod"},
        "responseStatus": {"metadata": {}, "code": 201},
        "requestObject": {
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "containers": [
                    {
                        "name": "worker",
                        "image": "ubuntu:latest",
                        "securityContext": {
                            "privileged": True,
                            "runAsUser": 0
                        }
                    }
                ]
            }
        },
        "stageTimestamp": ts(30)
    }
]

# ==============================================================================
# 5 DANGEROUS LOGS (Active Adversary / Privilege Escalation / Toxic Combinations)
# ==============================================================================

dangerous_logs = [
    {
        "_meta": {
            "id": "DANG-001",
            "category": "DANGEROUS",
            "threat_label": "Defense Evasion: Active CloudTrail Disabling & Trail Deletion",
            "mitre_technique": "T1562.001 - Impair Defenses: Disable Cloud Logs",
            "severity_assessment": "CRITICAL - Active Adversary Blinding SOC"
        },
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJCOMPROMISED01",
            "arn": "arn:aws:iam::112233445566:user/compromised-secops",
            "accountId": "112233445566",
            "userName": "compromised-secops"
        },
        "eventTime": ts(35),
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "185.220.101.5",  # Known Tor exit node
        "userAgent": "Boto3/1.28.1 Python/3.9.11 Linux",
        "requestParameters": {
            "name": "arn:aws:cloudtrail:us-east-1:112233445566:trail/enterprise-master-audit-trail"
        },
        "responseElements": None,
        "readOnly": False,
        "eventType": "AwsApiCall"
    },
    {
        "_meta": {
            "id": "DANG-002",
            "category": "DANGEROUS",
            "threat_label": "Toxic Combination: EC2 Role Credential Exfiltration Outside AWS",
            "mitre_technique": "T1552.005 - Cloud Instance Metadata API",
            "severity_assessment": "CRITICAL - Stolen STS Metadata Token Used from Foreign IP"
        },
        "schemaVersion": "2.0",
        "accountId": "112233445566",
        "region": "us-east-1",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.5,
        "createdAt": ts(41),
        "title": "Credentials for EC2 role 'prod-payment-processor' exfiltrated and invoked outside AWS infrastructure",
        "description": "IAM credentials belonging to instance profile 'prod-payment-processor' on instance i-084a921c were used from IP 194.26.29.112 outside the AWS network to call sts:GetCallerIdentity and s3:ListBuckets.",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "ASIAVEXAMPLEEXFIL01",
                "principalId": "AROAJEXAMPLEPAYMENT:i-084a921c",
                "userName": "prod-payment-processor",
                "userType": "AssumedRole"
            }
        },
        "service": {
            "serviceName": "guardduty",
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "ListBuckets",
                    "serviceName": "s3.amazonaws.com",
                    "callerType": "Remote IP",
                    "remoteIpDetails": {
                        "ipAddressV4": "194.26.29.112",
                        "organization": {"asnOrg": "Rogue Autonomous System Hosting"},
                        "country": {"countryName": "Seychelles"}
                    }
                }
            }
        }
    },
    {
        "_meta": {
            "id": "DANG-003",
            "category": "DANGEROUS",
            "threat_label": "Direct Privilege Escalation: Rogue User Attaching AdministratorAccess Policy",
            "mitre_technique": "T1098 - Account Manipulation",
            "severity_assessment": "CRITICAL - Full Cloud Account Takeover"
        },
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJBACKDOOR002",
            "arn": "arn:aws:iam::112233445566:user/ghost-service-worker",
            "accountId": "112233445566",
            "userName": "ghost-service-worker"
        },
        "eventTime": ts(48),
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "91.240.118.172",
        "requestParameters": {
            "userName": "ghost-service-worker",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        "responseElements": None,
        "readOnly": False,
        "eventType": "AwsApiCall"
    },
    {
        "_meta": {
            "id": "DANG-004",
            "category": "DANGEROUS",
            "threat_label": "Kubernetes Cluster Takeover: Anonymous Binding of cluster-admin Role",
            "mitre_technique": "T1078.004 - Cloud Accounts: Kubernetes RBAC",
            "severity_assessment": "CRITICAL - Complete Control Plane Compromise"
        },
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": "k8s-exploit-91a0f8-1182",
        "stage": "ResponseComplete",
        "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "verb": "create",
        "user": {"username": "system:anonymous", "groups": ["system:unauthenticated"]},
        "sourceIPs": ["45.154.255.89"],
        "objectRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "resource": "clusterrolebindings",
            "name": "system-backdoor-cluster-admin"
        },
        "responseStatus": {"metadata": {}, "code": 201},
        "requestObject": {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "system-backdoor-cluster-admin"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
            },
            "subjects": [
                {
                    "kind": "Group",
                    "name": "system:unauthenticated",
                    "apiGroup": "rbac.authorization.k8s.io"
                }
            ]
        },
        "stageTimestamp": ts(54)
    },
    {
        "_meta": {
            "id": "DANG-005",
            "category": "DANGEROUS",
            "threat_label": "GCP Ransomware Staging: Destruction of Cloud KMS CryptoKey + Disk Deletions",
            "mitre_technique": "T1485 - Data Destruction",
            "severity_assessment": "CRITICAL - Unrecoverable Enterprise Data Destruction"
        },
        "protoPayload": {
            "serviceName": "cloudkms.googleapis.com",
            "methodName": "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
            "resourceName": "projects/project-prod-9921/locations/global/keyRings/prod-db-keys/cryptoKeys/master-encryption-key/cryptoKeyVersions/1",
            "authenticationInfo": {"principalEmail": "compromised-sa@project-prod-9921.iam.gserviceaccount.com"},
            "request": {
                "name": "projects/project-prod-9921/locations/global/keyRings/prod-db-keys/cryptoKeys/master-encryption-key/cryptoKeyVersions/1"
            },
            "serviceData": {
                "action": "DESTROY_CRYPTO_KEY_VERSION"
            }
        },
        "timestamp": ts(59),
        "severity": "CRITICAL",
        "logName": "projects/project-prod-9921/logs/cloudaudit.googleapis.com%2Factivity"
    }
]

# ==============================================================================
# 90 REALISTIC BENIGN / ROUTINE CLOUD LOGS
# ==============================================================================

benign_templates = [
    # AWS CloudTrail benign calls
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "AWS IAM"},
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "userName": f"analyst-user-{i%10}", "accountId": "112233445566"},
        "eventTime": ts(i),
        "eventSource": "iam.amazonaws.com",
        "eventName": "GetAccountSummary",
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"10.0.{i%250}.12",
        "userAgent": "console.amazonaws.com",
        "responseElements": None,
        "readOnly": True
    },
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "AWS S3"},
        "eventVersion": "1.08",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:iam::112233445566:role/app-backend", "accountId": "112233445566"},
        "eventTime": ts(i),
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"172.31.{i%50}.4",
        "requestParameters": {"bucketName": "app-assets-production", "key": f"static/js/bundle-{i}.js"},
        "readOnly": True
    },
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "AWS STS"},
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "userName": "ci-cd-bot", "accountId": "112233445566"},
        "eventTime": ts(i),
        "eventSource": "sts.amazonaws.com",
        "eventName": "GetCallerIdentity",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "54.210.12.98",
        "readOnly": True
    },
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "AWS DynamoDB"},
        "eventVersion": "1.08",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:iam::112233445566:role/orders-microservice", "accountId": "112233445566"},
        "eventTime": ts(i),
        "eventSource": "dynamodb.amazonaws.com",
        "eventName": "GetItem",
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"10.100.{i%10}.5",
        "requestParameters": {"tableName": "CustomerOrdersProd", "key": {"order_id": {"S": f"ORD-{9000+i}"}}},
        "readOnly": True
    },
    # Azure Activity Logs
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "Azure Compute"},
        "time": ts(i),
        "resourceId": f"/subscriptions/sub-8491-prod/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web-{i%5}",
        "operationName": "Microsoft.Compute/virtualMachines/restart/action",
        "category": "Administrative",
        "resultType": "Success",
        "caller": "autoscaler-service@enterprise.onmicrosoft.com"
    },
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "Azure Storage"},
        "time": ts(i),
        "resourceId": f"/subscriptions/sub-8491-prod/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stlogs{i%3}",
        "operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
        "category": "Administrative",
        "resultType": "Success",
        "caller": "backup-worker@enterprise.onmicrosoft.com"
    },
    # GCP Cloud Audit Logs
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "GCP Compute"},
        "protoPayload": {
            "serviceName": "compute.googleapis.com",
            "methodName": "v1.compute.instances.get",
            "resourceName": f"projects/project-prod-9921/zones/us-central1-a/instances/backend-node-{i%8}",
            "authenticationInfo": {"principalEmail": "monitoring-agent@project-prod-9921.iam.gserviceaccount.com"}
        },
        "timestamp": ts(i),
        "severity": "INFO"
    },
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "GCP BigQuery"},
        "protoPayload": {
            "serviceName": "bigquery.googleapis.com",
            "methodName": "jobservice.jobcompleted",
            "resourceName": "projects/project-prod-9921/queries/query-job-7712",
            "authenticationInfo": {"principalEmail": f"analyst-{i%4}@enterprise.com"}
        },
        "timestamp": ts(i),
        "severity": "INFO"
    },
    # Kubernetes Audit Logs
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "Kubernetes Pods"},
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata",
        "stage": "ResponseComplete",
        "requestURI": f"/api/v1/namespaces/default/pods/nginx-ingress-{i%10}",
        "verb": "get",
        "user": {"username": "system:kube-scheduler"},
        "responseStatus": {"code": 200},
        "stageTimestamp": ts(i)
    },
    # AWS VPC Flow Logs
    lambda i: {
        "_meta": {"id": f"BENIGN-{i:03d}", "category": "BENIGN", "service": "AWS VPC Flow"},
        "version": 2,
        "accountId": "112233445566",
        "interfaceId": f"eni-0a81b94c{i%10}",
        "srcAddr": f"10.0.{i%20}.45",
        "dstAddr": "10.0.1.10",
        "srcPort": 49152 + (i * 13 % 10000),
        "dstPort": 443,
        "protocol": 6,
        "packets": 12 + (i % 50),
        "bytes": 1040 + (i * 128),
        "start": 1792548800 + i * 60,
        "end": 1792548860 + i * 60,
        "action": "ACCEPT",
        "logStatus": "OK"
    }
]

# Generate 90 benign logs (cycling through templates)
benign_logs = []
for idx in range(1, 91):
    template_fn = benign_templates[(idx - 1) % len(benign_templates)]
    benign_logs.append(template_fn(idx))

# Combine all 100 logs
# Interleave vulnerable and dangerous across the stream
all_100_logs = []
b_ptr = 0
v_ptr = 0
d_ptr = 0

for i in range(1, 101):
    if i in [15, 35, 55, 75, 95] and v_ptr < len(vulnerable_logs):
        all_100_logs.append(vulnerable_logs[v_ptr])
        v_ptr += 1
    elif i in [20, 40, 60, 80, 100] and d_ptr < len(dangerous_logs):
        all_100_logs.append(dangerous_logs[d_ptr])
        d_ptr += 1
    else:
        all_100_logs.append(benign_logs[b_ptr])
        b_ptr += 1

# Write JSONL format (line-delimited JSON)
jsonl_file = OUTPUT_DIR / "sample_telemetry_100.jsonl"
with open(jsonl_file, "w", encoding="utf-8") as f:
    for rec in all_100_logs:
        f.write(json.dumps(rec) + "\n")

# Write formatted JSON array format
json_file = OUTPUT_DIR / "sample_telemetry_100.json"
with open(json_file, "w", encoding="utf-8") as f:
    json.dump(all_100_logs, f, indent=2)

print(f"[+] Successfully generated 100 multi-cloud telemetry records!")
print(f"    - JSONL File: {jsonl_file} ({jsonl_file.stat().st_size / 1024:.1f} KB)")
print(f"    - JSON File:  {json_file} ({json_file.stat().st_size / 1024:.1f} KB)")
print(f"    - Composition: 90 Benign, 5 Vulnerable (CIS/NIST), 5 Dangerous (Attacker)")
