"""Unit tests for PrivacyScrubber."""

from cloudsec_rag.ingestion.privacy_scrubber import PrivacyScrubber


def test_scrub_aws_access_key():
    scrubber = PrivacyScrubber()
    sample = "Encountered issue with key AKIAIOSFODNN7EXAMPLE during s3 get"
    cleaned, count, breakdown = scrubber.scrub(sample)
    assert count == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "<REDACTED_AWS_ACCESS_KEY:***>" in cleaned


def test_scrub_jwt_and_password():
    scrubber = PrivacyScrubber()
    sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakPassword password: MySuperSecretPass!123"
    cleaned, count, _ = scrubber.scrub(sample)
    assert count >= 2
    assert "MySuperSecretPass!123" not in cleaned
    assert "Bearer eyJhbGci" not in cleaned


def test_pseudonymize_identifier():
    scrubber = PrivacyScrubber()
    anon1 = scrubber.pseudonymize_identifier("123456789012")
    anon2 = scrubber.pseudonymize_identifier("123456789012")
    assert anon1 == anon2
    assert anon1.startswith("ANON-")
