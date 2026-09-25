"""Unit tests for multi-cloud parsers."""

from cloudsec_rag.core.types import CloudProvider, Severity
from cloudsec_rag.ingestion.parsers import CloudTelemetryParser


def test_parse_presentation_s3_alert():
    # Exact scenario from PDF slide 6:
    # "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH code=CFG-0091"
    raw_log = "WARN: s3_bucket_policy=PUBLIC_READ resource=bkt-7841a region=ap-south-1 severity=HIGH code=CFG-0091"
    parser = CloudTelemetryParser()
    incident = parser.parse(raw_log)

    assert incident.provider == CloudProvider.AWS
    assert incident.resource_id == "bkt-7841a"
    assert incident.region == "ap-south-1"
    assert incident.severity_hint in [Severity.HIGH, Severity.CRITICAL]


def test_parse_kubernetes_yaml():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-microservice
  namespace: fintech
spec:
  template:
    spec:
      containers:
      - name: payment-api
        securityContext:
          privileged: true
"""
    parser = CloudTelemetryParser()
    incident = parser.parse(manifest)

    assert incident.provider == CloudProvider.KUBERNETES
    assert incident.resource_id == "fintech/Deployment/payment-microservice"
    assert incident.severity_hint == Severity.CRITICAL
