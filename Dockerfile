# syntax=docker/dockerfile:1

# ---- builder -----------------------------------------------------------
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY nmap_mcp ./nmap_mcp

RUN uv sync --frozen --no-dev

# ---- runtime -------------------------------------------------------------
FROM python:3.13-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap libcap2-bin \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin mcpuser \
    && mkdir -p /data \
    && chown -R mcpuser:mcpuser /data

WORKDIR /app
COPY --from=builder --chown=mcpuser:mcpuser /app/.venv /app/.venv
COPY --chown=mcpuser:mcpuser nmap_mcp ./nmap_mcp

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    NMAP_PRIVILEGED=1 \
    NMAP_HISTORY_DB=/data/history.db

USER mcpuser

ENTRYPOINT ["nmap-mcp"]
