"""Tool capability registry + inference from descriptions.

Capabilities describe what KIND of data a tool can read/write/send.
The capability graph uses these to decide whether a call is a sensitive
source or a dangerous sink.

Two sources of capabilities:
  1. Static registry (TOOL_CAPABILITIES) — well-known MCP server tools.
     This WINS on conflict (avoids inference false positives).
  2. Inference from tool description (on tools/list) — conservative
     keyword matching. Only ADDS capabilities; never assigns read:secret
     (that's source-detection's job on actual call args).

Capability taxonomy:
  Sources: read:filesystem  read:secret  read:env  read:database  read:network
  Sinks:   write:filesystem  network:send  exec:command  delete:filesystem  write:database
"""

from __future__ import annotations

import re
from typing import Optional

# Well-known tool name -> capabilities. Covers common MCP servers.
TOOL_CAPABILITIES: dict[str, list[str]] = {
    # filesystem server
    "read_file": ["read:filesystem"],
    "read_text_file": ["read:filesystem"],
    "write_file": ["write:filesystem"],
    "list_directory": ["read:filesystem"],
    "create_directory": ["write:filesystem"],
    "delete_file": ["delete:filesystem"],
    "move_file": ["write:filesystem"],
    "search_files": ["read:filesystem"],
    "get_file_info": ["read:filesystem"],
    # fetch / http server
    "fetch_url": ["read:network"],
    "http_request": ["read:network", "network:send"],
    "post_url": ["network:send"],
    "send_request": ["network:send"],
    # git server
    "git_status": ["read:filesystem"],
    "git_log": ["read:filesystem"],
    "git_run": ["read:filesystem", "exec:command"],
    # shell / exec servers
    "exec": ["exec:command"],
    "run_command": ["exec:command"],
    "execute": ["exec:command"],
    "shell": ["exec:command"],
    "bash": ["exec:command"],
    # database servers
    "sql_query": ["read:database"],
    "sql_execute": ["read:database", "write:database"],
    "read_query": ["read:database"],
    "write_query": ["write:database"],
    # env
    "get_env": ["read:env"],
    "list_env": ["read:env"],
}

# All known capability strings (for validation).
ALL_CAPABILITIES = {
    "read:filesystem", "read:secret", "read:env", "read:database", "read:network",
    "write:filesystem", "network:send", "exec:command", "delete:filesystem", "write:database",
}

SINK_CAPABILITIES = {
    "write:filesystem", "network:send", "exec:command",
    "delete:filesystem", "write:database",
}

SOURCE_CAPABILITIES = {
    "read:filesystem", "read:secret", "read:env", "read:database", "read:network",
}

# Inference patterns: (regex, capability). Matched against the description.
# Requires BOTH a verb and a noun to avoid false positives (e.g. "read the
# status" alone is not read:filesystem).
_INFER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(read|get|load|fetch|retrieve|list)\b.*\b(file|path|directory|folder|content)\b", re.IGNORECASE), "read:filesystem"),
    (re.compile(r"\b(write|save|create|update|modify|patch)\b.*\b(file|path|directory|folder)\b", re.IGNORECASE), "write:filesystem"),
    (re.compile(r"\b(delete|remove|rm|unlink)\b.*\b(file|path|directory|folder)\b", re.IGNORECASE), "delete:filesystem"),
    (re.compile(r"\b(fetch|get|request|download|curl|wget)\b.*\b(url|http|https|web|site)\b", re.IGNORECASE), "read:network"),
    (re.compile(r"\b(post|send|upload|submit|webhook|push)\b.*\b(url|http|https|web|site|endpoint)\b", re.IGNORECASE), "network:send"),
    (re.compile(r"\b(exec|execute|run|shell|bash|cmd|command|subprocess)\b.*\b(command|script|shell|process|program)\b", re.IGNORECASE), "exec:command"),
    (re.compile(r"\b(env|environment variables?)\b", re.IGNORECASE), "read:env"),
    (re.compile(r"\b(sql|query)\b.*\b(select|read|fetch)\b", re.IGNORECASE), "read:database"),
    (re.compile(r"\b(sql|query)\b.*\b(insert|update|delete|drop|write|create)\b", re.IGNORECASE), "write:database"),
]


def infer_capabilities(description: str) -> list[str]:
    """Infer capabilities from a tool description. Conservative.

    Only returns capabilities whose pattern matches. Never assigns
    read:secret (that's determined by source detection on actual args).
    """
    if not description:
        return []
    caps: list[str] = []
    for pat, cap in _INFER_PATTERNS:
        if pat.search(description) and cap not in caps:
            caps.append(cap)
    return caps


def get_capabilities(
    tool_name: str,
    description: str = "",
    registry: Optional[dict[str, list[str]]] = None,
) -> list[str]:
    """Return capabilities for a tool.

    Registry (static or user-supplied) takes precedence. If the tool is not
    in the registry, fall back to inference from the description. Inference
    only ADDS capabilities not already present from the registry.
    """
    reg = registry if registry is not None else TOOL_CAPABILITIES
    caps = list(reg.get(tool_name, []))
    if not caps:
        # Unknown to registry -> infer from description.
        caps = infer_capabilities(description)
    return caps
