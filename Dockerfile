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
# find / -xdev searches the whole device so the path never needs to be hardcoded.
ARG CACHEBUST=1
RUN find / -xdev -type d \
      \( -name "wheel-0.4[0-5]*.dist-info" \
         -o -name "jaraco.context-[0-5].*.dist-info" \) \
      -prune -exec rm -rf '{}' ';' 2>/dev/null; true

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "-u", "diagnose.py"]
