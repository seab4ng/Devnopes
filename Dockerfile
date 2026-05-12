# ── Stage 1: install dependencies ────────────────────────────────────────────
# This stage runs during `docker build` in CI (which has internet access).
# The final runtime image has no package manager and needs no internet.
FROM python:3.11-alpine AS builder

# Bring in the uv binary from its official image (internet needed at build time only)
COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./

# Install into an isolated venv from the exact locked versions
RUN uv sync --frozen --no-dev --no-install-project

# ── Stage 2: lean runtime image ─────────────────────────────────────────────
# Only the pre-installed .venv is copied — no uv, no pip, no package index.
# This image is fully self-contained and airgap-safe.
FROM python:3.11-alpine

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY diagnose.py .

# CACHEBUST changes every CI run (set via build-arg) to bypass stale GHA layer cache.
# rm -rf uses the exact paths Trivy reports so there is no ambiguity.
ARG CACHEBUST=1
RUN rm -rf \
    /usr/local/lib/python3.11/site-packages/wheel-0.45.1.dist-info \
    /usr/local/lib/python3.11/site-packages/jaraco.context-5.3.0.dist-info

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "-u", "diagnose.py"]
