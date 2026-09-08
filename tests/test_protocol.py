"""Tests for the JSON-RPC 2.0 protocol primitives."""
import io
import json

import pytest

from mcp_shield.protocol import (
    Message,
    ProtocolError,
    is_tools_call,
    is_tools_list,
    make_error_response,
    read_message,
    write_message,
)


def _msg(raw):
    return Message.from_dict(raw)


def test_request_is_request():
    m = _msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert m.is_request
    assert not m.is_notification
    assert not m.is_response


def test_notification_is_notification():
    m = _msg({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert m.is_notification
    assert not m.is_request


def test_response_is_response():
    m = _msg({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert m.is_response
    assert not m.is_request


def test_invalid_jsonrpc_version():
    with pytest.raises(ProtocolError):
        _msg({"jsonrpc": "1.0", "id": 1, "method": "x"})


def test_non_object_payload():
    with pytest.raises(ProtocolError):
        Message.from_dict([1, 2, 3])  # type: ignore[arg-type]


def test_to_bytes_roundtrip():
    raw = {"jsonrpc": "2.0", "id": 42, "method": "tools/list", "params": {}}
    m = _msg(raw)
    data = m.to_bytes()
    assert data.endswith(b"\n")
    parsed = json.loads(data.decode("utf-8").strip())
    assert parsed == raw


def test_read_message_simple():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    reader = io.BytesIO(payload)
    m = read_message(reader)
    assert m is not None
    assert m.method == "tools/list"
    assert m.id == 1


def test_read_message_eof():
    reader = io.BytesIO(b"")
    assert read_message(reader) is None


def test_read_message_truncated():
    reader = io.BytesIO(b'{"jsonrpc":"2.0",')  # no newline
    with pytest.raises(ProtocolError):
        read_message(reader)


def test_read_message_malformed_json():
    reader = io.BytesIO(b"not json\n")
    with pytest.raises(ProtocolError):
        read_message(reader)


def test_read_message_skip_blank_lines():
    payload = b'\n\n{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    reader = io.BytesIO(payload)
    m = read_message(reader)
    assert m is not None
    assert m.method == "tools/list"


def test_write_message_writes_and_flushes():
    buf = io.BytesIO()
    m = _msg({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    write_message(buf, m)
    assert buf.getvalue().endswith(b"\n")


def test_is_tools_list():
    assert is_tools_list(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    assert not is_tools_list(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}))


def test_is_tools_call():
    assert is_tools_call(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}))
    assert not is_tools_call(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))


def test_make_error_response():
    err = make_error_response(99, -32001, "blocked", data={"rule": "test"})
    assert err.id == 99
    assert err.error is not None
    assert err.error["code"] == -32001
    assert err.error["message"] == "blocked"
    assert err.error["data"] == {"rule": "test"}
