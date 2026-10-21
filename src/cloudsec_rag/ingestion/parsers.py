"""Multi-Cloud Telemetry & Misconfiguration Parsers.

Supports AWS CloudTrail/S3/IAM, Azure Activity/NSG, GCP Audit/IAM, and Kubernetes manifests.
"""

import json
import re
import uuid
from typing import Any, Dict, Optional
import yaml

from ..core.types import CloudProvider, CloudSecurityIncident, Severity
from .privacy_scrubber import PrivacyScrubber


class CloudTelemetryParser:
    """Parses raw text, JSON, or YAML logs from multiple cloud platforms into normalized incidents."""

    def __init__(self, scrubber: Optional[PrivacyScrubber] = None):
        self.scrubber = scrubber or PrivacyScrubber()

    def parse(self, raw_input: str, provider_hint: Optional[str] = None) -> CloudSecurityIncident:
        """Parse raw telemetry input into a standard CloudSecurityIncident."""
        cleaned_text = raw_input.strip()
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

        # 1. First redact sensitive credentials
        sanitized_payload, redacted_count, _ = self.scrubber.scrub(cleaned_text)

        # 2. Try JSON parsing
        try:
            data = json.loads(cleaned_text)
            return self._parse_json_event(incident_id, data, sanitized_payload, redacted_count, provider_hint)
        except json.JSONDecodeError:
            pass

        # 3. Try YAML parsing (Kubernetes or CloudFormation)
        try:
            yaml_data = yaml.safe_load(cleaned_text)
            if isinstance(yaml_data, dict) and ("apiVersion" in yaml_data or "Resources" in yaml_data):
                return self._parse_yaml_event(incident_id, yaml_data, sanitized_payload, redacted_count)
        except Exception:
            pass

        # 4. Fallback to Plain Text / Log line parsing
        return self._parse_text_log(incident_id, cleaned_text, sanitized_payload, redacted_count, provider_hint)

    def _parse_json_event(
        self, incident_id: str, data: Dict[str, Any], sanitized: str, redacted_count: int, hint: Optional[str]
    ) -> CloudSecurityIncident:
        # Check if telemetry is marked BENIGN or is safe read-only operational activity
        meta_cat = data.get("_meta", {}).get("category", "").upper() if isinstance(data.get("_meta"), dict) else ""
        data_str = json.dumps(data).lower()
        has_attack_markers = any(k in data_str for k in ["unauthorized", "exfil", "stoplogging", "attachuserpolicy", "cluster-admin", "allusers", "destroy", "0.0.0.0/0", "public_read", "privileged: true"])
        is_benign = (meta_cat == "BENIGN") or (data.get("readOnly") is True and not has_attack_markers)
        if is_benign:
            data["is_benign"] = True

        # Detect AWS CloudTrail
        if "eventSource" in data or "awsRegion" in data or "userIdentity" in data:
            resource_id = "unknown-aws-resource"
            if "resources" in data and isinstance(data["resources"], list) and len(data["resources"]) > 0:
                resource_id = data["resources"][0].get("ARN", data["resources"][0].get("name", "aws-res"))
            elif "requestParameters" in data and isinstance(data["requestParameters"], dict):
                params = data["requestParameters"]
                resource_id = params.get("bucketName") or params.get("roleName") or params.get("groupName") or "aws-param-res"
            elif "userIdentity" in data and isinstance(data["userIdentity"], dict) and "userName" in data["userIdentity"]:
                resource_id = f"iam-user/{data['userIdentity']['userName']}"

            sev = Severity.LOW if is_benign else self._infer_severity(data.get("eventName", "") + " " + json.dumps(data))
            return CloudSecurityIncident(
                incident_id=incident_id,
                provider=CloudProvider.AWS,
                resource_id=str(resource_id),
                event_name=data.get("eventName", "AWS_GENERIC_EVENT"),
                region=data.get("awsRegion", "global"),
                severity_hint=sev,
                raw_payload=json.dumps(data, indent=2),
                sanitized_payload=sanitized,
                secrets_redacted_count=redacted_count,
                metadata=data,
            )

        # Detect Azure Activity Log
        if "resourceId" in data or "operationName" in data or "subscriptionId" in data:
            sev = Severity.LOW if is_benign else self._infer_severity(json.dumps(data))
            return CloudSecurityIncident(
                incident_id=incident_id,
                provider=CloudProvider.AZURE,
                resource_id=data.get("resourceId", "azure-resource"),
                event_name=data.get("operationName", {}).get("value", data.get("operationName", "AzureEvent")),
                region=data.get("location", "azure-global"),
                severity_hint=sev,
                raw_payload=json.dumps(data, indent=2),
                sanitized_payload=sanitized,
                secrets_redacted_count=redacted_count,
                metadata=data,
            )

        # Detect GCP Cloud Audit Log
        if "protoPayload" in data or "resource" in data and "type" in data.get("resource", {}):
            proto = data.get("protoPayload", {})
            sev = Severity.LOW if is_benign else self._infer_severity(json.dumps(data))
            return CloudSecurityIncident(
                incident_id=incident_id,
                provider=CloudProvider.GCP,
                resource_id=proto.get("resourceName", "gcp-resource"),
                event_name=proto.get("methodName", "GCPEvent"),
                region=data.get("resource", {}).get("labels", {}).get("location", "gcp-global"),
                severity_hint=sev,
                raw_payload=json.dumps(data, indent=2),
                sanitized_payload=sanitized,
                secrets_redacted_count=redacted_count,
                metadata=data,
            )

        # Generic JSON log
        prov = CloudProvider.AWS if hint == "AWS" else CloudProvider.MULTI_CLOUD
        sev = Severity.LOW if is_benign else self._infer_severity(json.dumps(data))
        return CloudSecurityIncident(
            incident_id=incident_id,
            provider=prov,
            resource_id=str(data.get("resource_id", data.get("resource", "generic-resource"))),
            event_name=str(data.get("event", data.get("rule", "SecurityAlert"))),
            severity_hint=sev,
            raw_payload=json.dumps(data, indent=2),
            sanitized_payload=sanitized,
            secrets_redacted_count=redacted_count,
            metadata=data,
        )


    def _parse_yaml_event(
        self, incident_id: str, data: Dict[str, Any], sanitized: str, redacted_count: int
    ) -> CloudSecurityIncident:
        # Kubernetes Manifest
        kind = data.get("kind", "KubernetesObject")
        name = data.get("metadata", {}).get("name", "k8s-resource")
        namespace = data.get("metadata", {}).get("namespace", "default")
        resource_id = f"{namespace}/{kind}/{name}"

        return CloudSecurityIncident(
            incident_id=incident_id,
            provider=CloudProvider.KUBERNETES,
            resource_id=resource_id,
            event_name=f"K8sManifest_{kind}",
            region="cluster",
            severity_hint=self._infer_severity(yaml.dump(data)),
            raw_payload=yaml.dump(data),
            sanitized_payload=sanitized,
            secrets_redacted_count=redacted_count,
            metadata=data,
        )

    def _parse_text_log(
        self, incident_id: str, raw_text: str, sanitized: str, redacted_count: int, hint: Optional[str]
    ) -> CloudSecurityIncident:
        # Simple extraction heuristics for common patterns (e.g. from the presentation PDF:
        # "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH code=CFG-0091")
        res_match = re.search(r"resource=([a-zA-Z0-9_\-\.\/]+)", raw_text, re.IGNORECASE)
        resource_id = res_match.group(1) if res_match else "cloud-resource-001"

        region_match = re.search(r"region=([a-zA-Z0-9_\-]+)", raw_text, re.IGNORECASE)
        region = region_match.group(1) if region_match else "global"

        event_name = "CloudMisconfigurationAlert"
        if "s3_bucket_policy" in raw_text.lower():
            event_name = "S3BucketPolicyPublicRead"
            provider = CloudProvider.AWS
        elif "iam" in raw_text.lower() or "role" in raw_text.lower():
            event_name = "IAMOverlyPermissiveRole"
            provider = CloudProvider.AWS
        elif "nsg" in raw_text.lower() or "azure" in raw_text.lower():
            event_name = "AzureNSGUnrestrictedInbound"
            provider = CloudProvider.AZURE
        elif "gcp" in raw_text.lower() or "allusers" in raw_text.lower():
            event_name = "GCPStoragePublicExposure"
            provider = CloudProvider.GCP
        elif "kubernetes" in raw_text.lower() or "privileged" in raw_text.lower() or "hostpath" in raw_text.lower():
            event_name = "K8sPrivilegedContainer"
            provider = CloudProvider.KUBERNETES
        else:
            provider = CloudProvider.AWS if hint == "AWS" else CloudProvider.MULTI_CLOUD

        return CloudSecurityIncident(
            incident_id=incident_id,
            provider=provider,
            resource_id=resource_id,
            event_name=event_name,
            region=region,
            severity_hint=self._infer_severity(raw_text),
            raw_payload=raw_text,
            sanitized_payload=sanitized,
            secrets_redacted_count=redacted_count,
            metadata={"source": "plain_text_log"},
        )

    def _infer_severity(self, text: str) -> Severity:
        lower = text.lower()
        if any(w in lower for w in ["critical", "public_read", "root", "allusers", "0.0.0.0/0", "privileged: true", "admin"]):
            return Severity.CRITICAL
        if any(w in lower for w in ["high", "unrestricted", "wildcard", "unencrypted", "cve"]):
            return Severity.HIGH
        if any(w in lower for w in ["medium", "warn", "mfa"]):
            return Severity.MEDIUM
        return Severity.LOW
