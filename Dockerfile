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

# Remove HIGH-CVE packages from system Python — not used at runtime (app runs from .venv).
# pip uninstall removes files+dist-info; the find is a fallback in case pip leaves stragglers.
RUN pip uninstall -y wheel "jaraco.context" 2>/dev/null || true \
    && find /usr/local/lib/python3.11/site-packages -maxdepth 1 -type d \
         \( -name "wheel-*.dist-info" -o -name "jaraco.context-*.dist-info" \) \
         -exec rm -rf {} +

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "-u", "diagnose.py"]
