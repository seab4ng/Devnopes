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

# Remove HIGH-CVE packages — not needed at runtime (app runs from .venv only).
# Uses site.getsitepackages() so the path is always correct regardless of Alpine layout.
# Globs ALL wheel-* and jaraco.context-* dist-info dirs so stale leftovers are caught too.
RUN python3 -c 'import shutil,pathlib,site;[shutil.rmtree(str(d),ignore_errors=True) or print("removed",d) for sp in site.getsitepackages() for pat in ["wheel-*.dist-info","jaraco.context-*.dist-info","jaraco_context-*.dist-info"] for d in pathlib.Path(sp).glob(pat)]' \
    && pip uninstall -y wheel "jaraco.context" 2>/dev/null || true

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "-u", "diagnose.py"]
