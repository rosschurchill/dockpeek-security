FROM python:3.11-slim

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

ENV VERSION=${VERSION} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/dockpeek/dockpeek" \
      org.opencontainers.image.url="https://github.com/dockpeek/dockpeek" \
      org.opencontainers.image.documentation="https://github.com/dockpeek/dockpeek#readme" \
      org.opencontainers.image.title="Dockpeek" \
      org.opencontainers.image.description="Quick Access & Easy Updates for Your Docker Containers"

RUN apt-get update && apt-get install -y \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt .

# Upgrade pip/wheel/setuptools first so base-image versions are replaced
# in this layer (prevents Trivy detecting stale versions from lower layers).
RUN pip install --no-cache-dir --upgrade pip wheel setuptools && \
    pip install --no-cache-dir -r requirements.txt

COPY gunicorn.conf.py .

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=3 \
  CMD curl -fsS http://localhost:${PORT:-8000}/health || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "run:app"]