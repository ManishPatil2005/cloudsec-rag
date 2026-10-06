# ==============================================================================
# CloudSec-RAG Enterprise Container Image
# Multi-stage secure build with non-root runtime user
# ==============================================================================

FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final Runtime Stage
FROM python:3.11-slim

WORKDIR /app

# Security: Create non-root dedicated security service user
RUN groupadd -r cloudsec && useradd -r -g cloudsec -u 10001 cloudsec

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Copy application source & config
COPY . .

# Ensure data directories exist and are owned by non-root user
RUN mkdir -p data/sessions data/benchmarks && \
    chown -R cloudsec:cloudsec /app

USER cloudsec

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    APP_PORT=8080 \
    APP_HOST=0.0.0.0

EXPOSE 8080

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health')" || exit 1

ENTRYPOINT ["python", "main.py", "serve", "--host", "0.0.0.0", "--port", "8080"]
