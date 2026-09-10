# Contributing

Thanks for helping improve MCP Shield.

## Development

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[cloud,test]"
pytest -q
```

Useful smoke scripts (optional):

```bash
python tests/smoke_proxy.py
python tests/smoke_injection.py
python tests/smoke_chain.py
python tests/protection_simulation.py
```

## Guidelines

- Keep the **policy engine deterministic** — never put an LLM on the final allow/deny path.
- Prefer fail-closed behavior for security controls that are enabled.
- Add/adjust tests with behavioral changes.
- Do not commit secrets, `.env`, real audit logs, or production DB dumps.

## Security bugs

See [`SECURITY.md`](SECURITY.md) — please use private disclosure for vulnerabilities.

## Design docs

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md)
