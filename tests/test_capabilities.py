"""Tests for capability registry + inference."""
from mcp_shield.graph.capabilities import (
    get_capabilities, infer_capabilities, TOOL_CAPABILITIES,
    SINK_CAPABILITIES, SOURCE_CAPABILITIES,
)


def test_registry_known_filesystem():
    assert get_capabilities("read_file") == ["read:filesystem"]


def test_registry_known_exec():
    assert "exec:command" in get_capabilities("exec")


def test_registry_known_network():
    caps = get_capabilities("fetch_url")
    assert "read:network" in caps


def test_registry_unknown_infer_filesystem():
    caps = get_capabilities("my_reader", description="read a file from disk")
    assert "read:filesystem" in caps


def test_infer_network():
    caps = get_capabilities("my_fetcher", description="fetch a URL and return content")
    assert "read:network" in caps


def test_infer_exec():
    caps = get_capabilities("runner", description="execute a shell command")
    assert "exec:command" in caps


def test_infer_send():
    caps = get_capabilities("poster", description="post data to a webhook URL")
    assert "network:send" in caps


def test_registry_overrides_inference():
    # read_file is in registry as read:filesystem; description says exec.
    # Registry wins -> only read:filesystem.
    caps = get_capabilities("read_file", description="execute commands")
    assert caps == ["read:filesystem"]


def test_no_match_returns_empty():
    assert get_capabilities("mystery", description="does nothing useful") == []


def test_empty_description_unknown_tool():
    assert get_capabilities("mystery_tool") == []


def test_infer_env():
    caps = get_capabilities("envtool", description="read environment variables")
    assert "read:env" in caps


def test_infer_database_read():
    caps = get_capabilities("dbtool", description="run a SQL SELECT query")
    assert "read:database" in caps


def test_infer_database_write():
    caps = get_capabilities("dbtool", description="run a SQL INSERT statement")
    assert "write:database" in caps


def test_inference_requires_verb_and_noun():
    # "read the status" alone should NOT infer read:filesystem (no file noun).
    caps = infer_capabilities("read the status of the server")
    assert "read:filesystem" not in caps


def test_user_registry_override():
    custom = {"my_tool": ["read:secret"]}
    assert get_capabilities("my_tool", registry=custom) == ["read:secret"]


def test_sink_and_source_sets_disjoint():
    # A capability is either a source or a sink (not both) in our taxonomy.
    assert SINK_CAPABILITIES.isdisjoint(SOURCE_CAPABILITIES)


def test_all_capabilities_in_taxonomy():
    for caps in TOOL_CAPABILITIES.values():
        for c in caps:
            assert c in SOURCE_CAPABILITIES or c in SINK_CAPABILITIES, f"unknown cap: {c}"
