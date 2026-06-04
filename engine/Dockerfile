# syntax=docker/dockerfile:1.7
# ==============================================================================
# wafeval engine container — Phase 3.
# Runs inside the `waflab` network so it resolves Traefik at traefik:80 and
# does not require host port mapping.
# ==============================================================================
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && \
    pip install --prefix=/install .

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN useradd --system --uid 10001 --home-dir /work wafeval && \
    mkdir -p /work /results && chown wafeval:wafeval /work /results

COPY --from=builder /install /usr/local
COPY --from=builder /build/src /app/src

USER wafeval
WORKDIR /work
ENV PYTHONPATH=/app/src \
    RESULTS_ROOT=/results \
    TRAEFIK_URL=http://traefik:80

ENTRYPOINT ["wafeval"]
CMD ["run", "--help"]
