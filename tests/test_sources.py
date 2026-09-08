"""Tests for sensitive source detection + fingerprinting."""
from types import SimpleNamespace

from mcp_shield.graph.sources import (
    is_sensitive_source, extract_sensitive_values_from_response,
    fingerprint, fingerprint_arg_values, fingerprint_redactions,
)


# --- is_sensitive_source --------------------------------------------------

def test_ssh_key_path():
    s, label = is_sensitive_source("read_file", {"path": "~/.ssh/id_rsa"}, ["read:filesystem"])
    assert s and label == "secret:ssh_key"


def test_aws_creds_path():
    s, label = is_sensitive_source("read_file", {"path": "~/.aws/credentials"}, ["read:filesystem"])
    assert s and label == "secret:aws_creds"


def test_benign_path():
    s, label = is_sensitive_source("read_file", {"path": "/tmp/report.txt"}, ["read:filesystem"])
    assert not s


def test_pem_file():
    s, label = is_sensitive_source("read_file", {"path": "/keys/server.pem"}, ["read:filesystem"])
    assert s and label == "secret:pem_key"


def test_key_file():
    s, label = is_sensitive_source("read_file", {"path": "/keys/private.key"}, ["read:filesystem"])
    assert s and label == "secret:key_file"


def test_env_file():
    s, label = is_sensitive_source("read_file", {"path": "~/.env"}, ["read:filesystem"])
    assert s and label == "secret:env_file"


def test_not_a_read_capability():
    # write_file is not a source capability -> not sensitive.
    s, _ = is_sensitive_source("write_file", {"path": "~/.ssh/id_rsa"}, ["write:filesystem"])
    assert not s


def test_nested_args():
    s, label = is_sensitive_source("read_file", {"opts": {"file": "~/.ssh/id_rsa"}}, ["read:filesystem"])
    assert s and label == "secret:ssh_key"


def test_path_in_list():
    s, label = is_sensitive_source("read_file", {"files": ["/tmp/x", "~/.ssh/id_rsa"]}, ["read:filesystem"])
    assert s and label == "secret:ssh_key"


# --- extract_sensitive_values_from_response -------------------------------

def test_redaction_provides_secret():
    red = SimpleNamespace(original="AKIAIOSFODNN7EXAMPLE", name="aws_access_key_id")
    vals = extract_sensitive_values_from_response([red], "")
    assert ("secret:aws_access_key_id", "AKIAIOSFODNN7EXAMPLE") in vals


def test_env_var_secret_in_response():
    text = "API_KEY=sk-abc123def456ghi789\nPATH=/usr/bin\n"
    vals = extract_sensitive_values_from_response([], text)
    labels = [v[0] for v in vals]
    assert "env:API_KEY" in labels
    # PATH is not a secret-ish name -> not included.
    assert not any(l == "env:PATH" for l in labels)


def test_env_var_benign_not_included():
    text = "USERNAME=bob\nHOME=/home/bob\n"
    vals = extract_sensitive_values_from_response([], text)
    assert not any(l.startswith("env:") for l, _ in vals)


def test_short_value_skipped():
    # Redaction original too short (<8) -> skip (avoid noise).
    red = SimpleNamespace(original="short", name="x")
    vals = extract_sensitive_values_from_response([red], "")
    assert not any(v[1] == "short" for v in vals)


# --- fingerprint ----------------------------------------------------------

def test_fingerprint_stable():
    assert fingerprint("abc") == fingerprint("abc")


def test_fingerprint_different():
    assert fingerprint("abc") != fingerprint("abd")


def test_fingerprint_size():
    assert len(fingerprint("abc", size=16)) == 16
    assert len(fingerprint("abc", size=8)) == 8


def test_fingerprint_arg_values_whole():
    fps = fingerprint_arg_values({"body": "my-secret-value"})
    assert fingerprint("my-secret-value") in fps


def test_fingerprint_arg_values_secret_as_whole_arg():
    # Realistic exfil case: agent passes the secret directly as the arg value.
    secret = "AKIAIOSFODNN7EXAMPLE"
    fps = fingerprint_arg_values({"body": secret})
    assert fingerprint(secret) in fps


def test_fingerprint_arg_values_nested():
    fps = fingerprint_arg_values({"opts": {"body": "nested-secret"}})
    assert fingerprint("nested-secret") in fps


def test_fingerprint_arg_values_skips_non_string():
    fps = fingerprint_arg_values({"n": 42, "b": True, "s": "str-val"})
    assert fingerprint("str-val") in fps


def test_fingerprint_arg_values_empty():
    assert fingerprint_arg_values({}) == set()


def test_fingerprint_redactions():
    red = SimpleNamespace(original="AKIAIOSFODNN7EXAMPLE", name="aws_access_key_id")
    fps = fingerprint_redactions([red])
    assert fingerprint("AKIAIOSFODNN7EXAMPLE") in fps


def test_fingerprint_redactions_skips_short():
    red = SimpleNamespace(original="short", name="x")
    assert fingerprint_redactions([red]) == set()
