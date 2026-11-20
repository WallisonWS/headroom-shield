# Multi-stage CIS-Hardened Non-Root Container for Headroom Shield Proxy & MCP Server
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEADROOM_SHIELD_TELEMETRY=off

RUN useradd --create-home --shell /sbin/nologin shielduser
WORKDIR /app

COPY --chown=shielduser:shielduser headroom_shield ./headroom_shield
COPY --chown=shielduser:shielduser pyproject.toml LICENSE NOTICE README.md ./

USER shielduser
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health')" || exit 1

ENTRYPOINT ["python3", "-m", "headroom_shield.proxy_server", "--host", "0.0.0.0", "--port", "8787"]
