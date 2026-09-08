"""Tests for the secret redactor."""
from mcp_shield.redactor import SecretRedactor


def test_no_secrets():
    r = SecretRedactor()
    out, reds = r.redact("hello world")
    assert out == "hello world"
    assert reds == []


def test_redacts_aws_access_key():
    r = SecretRedactor()
    out, reds = r.redact("my key is AKIAIOSFODNN7EXAMPLE thanks")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:aws_access_key_id]" in out
    assert len(reds) == 1
    assert reds[0].name == "aws_access_key_id"


def test_redacts_github_pat():
    r = SecretRedactor()
    token = "ghp_" + "a" * 36
    out, _ = r.redact(f"token={token}")
    assert token not in out
    assert "[REDACTED:github_pat]" in out


def test_redacts_openai_key():
    r = SecretRedactor()
    key = "sk-" + "a" * 30
    out, reds = r.redact(f"OPENAI_API_KEY={key}")
    assert key not in out
    assert len(reds) >= 1


def test_redacts_slack_token():
    r = SecretRedactor()
    token = "xoxb-" + "1" * 10 + "-" + "a" * 24
    out, reds = r.redact(f"slack: {token}")
    assert token not in out
    assert any(rr.name == "slack_token" for rr in reds)


def test_redacts_private_key_pem_header():
    r = SecretRedactor()
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    out, reds = r.redact(pem)
    # The PEM pattern only matches the header line, not the body.
    assert "-----BEGIN RSA PRIVATE KEY-----" not in out
    assert any(rr.name == "private_key_pem" for rr in reds)


def test_redacts_dict_recursively():
    r = SecretRedactor()
    data = {
        "url": "https://api.example.com",
        "headers": {"Authorization": "Bearer abc123def456ghi789jkl012"},
        "body": {"token": "ghp_" + "b" * 36, "nested": {"deep": "sk-" + "c" * 20}},
    }
    out, reds = r.redact_dict(data)
    # All secrets gone from the output.
    assert "ghp_" + "b" * 36 not in str(out)
    assert "sk-" + "c" * 20 not in str(out)
    # At least two redactions happened.
    assert len(reds) >= 2


def test_redact_non_string_value():
    r = SecretRedactor()
    out, reds = r.redact_dict({"count": 42, "flag": True, "secret": "ghp_" + "a" * 36})
    assert out["count"] == 42
    assert out["flag"] is True
    assert "ghp_" + "a" * 36 not in out["secret"]


def test_redact_list_values():
    r = SecretRedactor()
    data = {"items": ["safe", "ghp_" + "a" * 36, {"deep": "sk-" + "x" * 20}]}
    out, reds = r.redact_dict(data)
    assert "ghp_" + "a" * 36 not in str(out)
    assert "sk-" + "x" * 20 not in str(out)
    assert len(reds) >= 2


def test_mask_keeps_prefix_suffix():
    r = SecretRedactor()
    token = "ghp_" + "a" * 36
    out, _ = r.redact(token)
    # Mask should keep first 4 chars visible for debuggability.
    assert out.startswith("ghp_")
    assert "[REDACTED:github_pat]" in out
