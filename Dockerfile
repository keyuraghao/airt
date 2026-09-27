# AISRF gateway image. Build: docker build -t aisrf . ; Run: docker run -p 8080:8080 --env-file .env aisrf
# syntax=docker/dockerfile:1.6

# --- stage 1: build a wheel and a virtualenv with every runtime dependency ---------------
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN pip install --upgrade pip build
COPY pyproject.toml README.md LICENSE ./
COPY aisrf ./aisrf
RUN python -m build --wheel --outdir /build/dist
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "$(ls /build/dist/aisrf-*.whl)[postgres]" "mcp>=1.0" "reportlab>=4" "openpyxl>=3.1"

# --- stage 2: minimal runtime ------------------------------------------------------------
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="AISRF" \
      org.opencontainers.image.description="AI Security & Research Framework: human-in-the-loop interception, analysis and red teaming for LLM traffic" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    AISRF_HOST=0.0.0.0 AISRF_PORT=8080 \
    AISRF_DATA_DIR=/app/data AISRF_LOG_DIR=/app/logs \
    AISRF_DATABASE_URL=sqlite+aiosqlite:////app/data/aisrf.db \
    AISRF_LOG_JSON_CONSOLE=true
RUN apt-get update && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 aisrf \
 && useradd --system --uid 10001 --gid aisrf --home-dir /app --shell /usr/sbin/nologin aisrf \
 && mkdir -p /app/data /app/logs \
 && chown -R aisrf:aisrf /app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER aisrf
VOLUME ["/app/data", "/app/logs"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${AISRF_PORT}/healthz" || exit 1
ENTRYPOINT ["aisrf"]
CMD ["serve"]
