"""JSON-RPC 2.0 protocol primitives used by MCP (Model Context Protocol).

MCP uses JSON-RPC 2.0 messages framed with newlines over stdio (the most
common transport for local MCP servers). This module provides:

- `Message` — a typed wrapper around a JSON-RPC 2.0 message (request,
  response, or notification).
- `read_message(reader)` / `write_message(writer, message)` — newline
  delimited framing with strict size limits to protect against resource
  exhaustion.
- `is_tools_list(msg)` / `is_tools_call(msg)` — helpers used by the proxy
  to decide which messages need interception.

The protocol is intentionally minimal — we only model what the proxy needs
to inspect and forward. We do not implement the full MCP capability
negotiation here; that is left to the real MCP client and server on either
side of the proxy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import IO, Any, Optional

# Hard limits to protect the proxy itself from abuse.
MAX_MESSAGE_BYTES = 4 * 1024 * 1024  # 4 MiB — generous; MCP messages are small.
ENCODING = "utf-8"

# JSON-RPC 2.0 method names that the proxy intercepts.
METHOD_TOOLS_LIST = "tools/list"
METHOD_TOOLS_CALL = "tools/call"
METHOD_INITIALIZE = "initialize"

INTERCEPTED_METHODS = {METHOD_TOOLS_LIST, METHOD_TOOLS_CALL}


class ProtocolError(ValueError):
    """Raised when a message cannot be parsed or violates JSON-RPC 2.0."""


@dataclass
class Message:
    """A JSON-RPC 2.0 message.

    Either a request (has method and id), a notification (has method,
    no id), or a response (has result/error and id). We keep the raw
    payload so we can forward unchanged bytes to the downstream server.
    """

    raw: dict[str, Any]
    # Convenience accessors (None for fields not present in this message).
    id: Optional[int | str] = None
    method: Optional[str] = None
    params: Optional[dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[dict[str, Any]] = None

    @property
    def is_request(self) -> bool:
        return self.method is not None and self.id is not None

    @property
    def is_notification(self) -> bool:
        return self.method is not None and self.id is None

    @property
    def is_response(self) -> bool:
        return self.id is not None and (self.result is not None or self.error is not None)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Message":
        if not isinstance(payload, dict):
            raise ProtocolError(f"Top-level JSON must be an object, got {type(payload).__name__}")
        if payload.get("jsonrpc") != "2.0":
            raise ProtocolError("Not a JSON-RPC 2.0 message (missing or wrong 'jsonrpc' field)")
        return cls(
            raw=payload,
            id=payload.get("id"),
            method=payload.get("method"),
            params=payload.get("params"),
            result=payload.get("result"),
            error=payload.get("error"),
        )

    def to_bytes(self) -> bytes:
        line = json.dumps(self.raw, ensure_ascii=False, separators=(",", ":"))
        return (line + "\n").encode(ENCODING)


def read_message(reader: IO[bytes]) -> Optional[Message]:
    """Read one newline-delimited JSON-RPC 2.0 message from `reader`.

    Returns None on EOF. Raises ProtocolError on malformed or oversized
    messages. We read byte-by-byte up to the newline to avoid blocking on
    partial buffered reads — MCP stdio is line-framed.
    """
    buf = bytearray()
    while True:
        chunk = reader.read(1)
        if not chunk:
            # EOF — if we have partial data, that's a truncated message.
            if buf:
                raise ProtocolError("Truncated message at EOF")
            return None
        if chunk == b"\n":
            break
        if chunk == b"\r":
            # Tolerate CRLF; the next byte should be \n.
            continue
        buf.extend(chunk)
        if len(buf) > MAX_MESSAGE_BYTES:
            raise ProtocolError(f"Message exceeds {MAX_MESSAGE_BYTES} bytes")

    if not buf:
        # Empty line — skip (some clients send keepalive newlines).
        return read_message(reader)

    try:
        payload = json.loads(buf.decode(ENCODING))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Malformed JSON: {exc}") from exc

    return Message.from_dict(payload)


def write_message(writer: IO[bytes], message: Message) -> None:
    """Write one newline-delimited JSON-RPC 2.0 message to `writer`."""
    data = message.to_bytes()
    if b"\n" in data[:-1]:
        raise ProtocolError("Message contains embedded newline")
    writer.write(data)
    writer.flush()


def is_tools_list(msg: Message) -> bool:
    return msg.method == METHOD_TOOLS_LIST


def is_tools_call(msg: Message) -> bool:
    return msg.method == METHOD_TOOLS_CALL


def make_error_response(id_: int | str, code: int, message: str, data: Optional[dict] = None) -> Message:
    """Build a JSON-RPC 2.0 error response — used when the proxy blocks a call."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return Message(
        raw={"jsonrpc": "2.0", "id": id_, "error": error},
        id=id_,
        error=error,
    )


# JSON-RPC error codes we use to signal why a call was blocked.
ERR_POLICY_DENIED = -32001          # matched a deny rule
ERR_INJECTION_DETECTED = -32002       # prompt injection in args or response
ERR_SECRET_IN_ARGS = -32003           # caller tried to exfiltrate a secret
ERR_CHAIN_BLOCKED = -32004             # cross-server exfiltration chain
ERR_APPROVAL_TIMEOUT = -32005          # human approval did not arrive in time
ERR_APPROVAL_DENIED = -32006           # human explicitly rejected the call
ERR_VALIDATION_FAILED = -32007          # argument failed allowlist validation
