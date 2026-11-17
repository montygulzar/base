"""Unit tests for the secrets scanner regex rules."""
from app.modules.secrets_scan import COMPILED


def test_rules_match_known_samples():
    samples = {
        "aws_access_key_id":   "AKIAIOSFODNN7EXAMPLE",
        "github_token":        "ghp_1234567890abcdef1234567890abcdef1234",
        "google_api_key":      "AIzaSy" + "0" * 33,  # 4 + 35 chars
        "private_key":         "-----BEGIN RSA PRIVATE KEY-----",
        "jwt":                 "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg_hijklm",
        "slack_token":         "xoxb-12345-67890-abcDEF",
    }
    hits = {name: False for name in samples}
    for name, rx, _ in COMPILED:
        if name in samples and rx.search(samples[name]):
            hits[name] = True
    missed = [k for k, v in hits.items() if not v]
    assert not missed, f"rules failed to match samples: {missed}"
