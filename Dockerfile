# Falcon Rego Toolkit
#
# Build the frontend before building this image:
#   cd frontend && npm install && npm run build
#
# Then build:
#   docker build -t falcon-rego-toolkit .

FROM python:3.13-slim

# Install OPA binary
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    OPA_ARCH=$(case "${TARGETARCH}" in "arm64") echo "arm64_static" ;; *) echo "amd64_static" ;; esac) && \
    curl -fsSL "https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_${OPA_ARCH}" -o /usr/local/bin/opa && \
    chmod +x /usr/local/bin/opa && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend source
COPY backend/ backend/

# Copy pre-built frontend (run `cd frontend && npm run build` first)
COPY frontend/dist frontend/dist

# Copy agent KB (useful reference files, no secrets)
COPY agent_kb/ agent_kb/

# Copy example policies
COPY simple_examples/ simple_examples/

ENV ENV=production \
    PYTHONUNBUFFERED=1 \
    CORS_ORIGINS="*"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["python", "backend/run.py"]
