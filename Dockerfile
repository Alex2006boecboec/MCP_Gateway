# MCP Shield Cloud Dashboard - Railway deployment
FROM python:3.12-slim

WORKDIR /app

# Install system deps (none needed beyond Python).
# Copy project files.
COPY pyproject.toml ./
COPY mcp_shield/ ./mcp_shield/
COPY README.md ./

# Install the package with the [cloud] extra.
RUN pip install --no-cache-dir ".[cloud]"

# Create a data directory for the SQLite DB (mounted as a volume on Railway).
RUN mkdir -p /app/data
ENV MCP_SHIELD_DB_PATH=/app/data/mcp_shield_cloud.db

# Railway provides PORT env var; uvicorn must bind to 0.0.0.0.
ENV MCP_SHIELD_HOST=0.0.0.0
ENV MCP_SHIELD_PORT=8000

EXPOSE 8000

# Run the cloud dashboard server.
CMD ["python", "-m", "mcp_shield.cloud.server"]
