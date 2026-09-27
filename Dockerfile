# AIRT gateway image. Build: docker build -t airt . ; Run: docker run -p 8080:8080 --env-file .env airt
# syntax=docker/dockerfile:1.6

# --- stage 1: build a wheel and a virtualenv with every runtime dependency ---------------
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN pip install --upgrade pip build
COPY pyproject.toml README.md LICENSE ./
COPY airt ./airt
RUN python -m build --wheel --outdir /build/dist
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "$(ls /build/dist/airt-*.whl)[postgres]" "mcp>=1.0" "reportlab>=4" "openpyxl>=3.1"

# --- stage 2: minimal runtime ------------------------------------------------------------
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="AIRT" \
      org.opencontainers.image.description="Enterprise AI red team gateway: human-in-the-loop interception, analysis and red teaming for LLM traffic" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    AIRT_HOST=0.0.0.0 AIRT_PORT=8080 \
    AIRT_DATA_DIR=/app/data AIRT_LOG_DIR=/app/logs \
    AIRT_DATABASE_URL=sqlite+aiosqlite:////app/data/airt.db \
    AIRT_LOG_JSON_CONSOLE=true
RUN apt-get update && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 airt \
 && useradd --system --uid 10001 --gid airt --home-dir /app --shell /usr/sbin/nologin airt \
 && mkdir -p /app/data /app/logs \
 && chown -R airt:airt /app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER airt
VOLUME ["/app/data", "/app/logs"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${AIRT_PORT}/healthz" || exit 1
ENTRYPOINT ["airt"]
CMD ["serve"]
