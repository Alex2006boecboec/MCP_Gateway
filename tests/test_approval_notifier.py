"""Tests for the approval notifier (best-effort, never raises)."""
import json
from unittest.mock import patch, MagicMock
from io import BytesIO

from mcp_shield.approval.notifier import notify, _format_message
from mcp_shield.approval.types import ApprovalRequest


def _req():
    return ApprovalRequest(
        request_id="abc123",
        call_id=1,
        server="fs",
        tool="exec",
        args={"cmd": "ls"},
        reason="high risk",
        trigger="risk-rule",
        rule_name="exec-rule",
        created_at=0.0,
        expires_at=120.0,
    )


def test_notify_success():
    """Mock urlopen to return a 200 -> notify returns True."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok = notify("https://hooks.slack.com/test", _req(), timeout=5.0)
    assert ok is True


def test_notify_failure_non_2xx():
    """Mock urlopen to return 500 -> notify returns False (no raise)."""
    mock_resp = MagicMock()
    mock_resp.status = 500
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok = notify("https://hooks.slack.com/test", _req(), timeout=5.0)
    assert ok is False


def test_notify_unreachable():
    """Mock a URLError -> notify returns False (no raise)."""
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no connection")):
        ok = notify("https://hooks.slack.com/test", _req(), timeout=5.0)
    assert ok is False


def test_notify_no_url():
    """webhook_url=None -> notify returns False (skipped, no raise)."""
    assert notify(None, _req(), timeout=5.0) is False


def test_notify_empty_url():
    """Empty string webhook_url -> notify returns False (skipped)."""
    assert notify("", _req(), timeout=5.0) is False


def test_format_message_contains_key_info():
    msg = _format_message(_req())
    assert "exec" in msg
    assert "fs" in msg
    assert "high risk" in msg
    assert "abc123" in msg
    assert "risk-rule" in msg


def test_format_message_includes_response_instructions():
    msg = _format_message(_req())
    assert "approve" in msg
    assert "deny" in msg
    assert "abc123.json" in msg


def test_notify_sends_json_payload():
    """Verify the POST body is valid JSON with a text field."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["data"] = req.data
        captured["headers"] = req.headers
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        notify("https://hooks.slack.com/test", _req(), timeout=5.0)

    payload = json.loads(captured["data"].decode("utf-8"))
    assert "text" in payload
    assert "exec" in payload["text"]
