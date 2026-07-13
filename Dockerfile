# syntax=docker/dockerfile:1
# MITRE CSD-H web UI — multi-stage build (React frontend + FastAPI backend).
#
# The versioned base tags make routine rebuilds predictable.  For a regulated
# deployment, replace each tag with the reviewed multi-architecture digest
# recorded in WEB_DEPLOYMENT_OPERATIONS.md before promotion.

# ---- Stage 1: build the React frontend ----
FROM node:20.20-bookworm-slim AS frontend-build
WORKDIR /build/webapp/frontend

# Install from the committed lockfile before source code so dependency caching
# remains useful without putting local node_modules in the build context.
COPY webapp/frontend/package.json webapp/frontend/package-lock.json ./
RUN npm ci
COPY webapp/frontend/ ./
RUN npm run build

# ---- Stage 2: Python backend + graph engine, serving the built frontend ----
FROM python:3.14.6-slim-trixie AS final

# WeasyPrint's native runtime dependencies.  Keep the base distribution
# explicit: libgdk-pixbuf-2.0-0 is the Debian trixie package name.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build dependencies before application source for a small, cacheable layer.
COPY requirements.txt ./
COPY webapp/backend/requirements.txt ./webapp/backend/requirements.txt
RUN pip install -r requirements.txt \
    && pip install -r webapp/backend/requirements.txt

# The image has a dedicated non-root identity.  Docker Compose may map the
# process to the host user's numeric UID/GID for a writable bind-mounted data
# directory; source files stay readable either way.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --create-home --shell /usr/sbin/nologin appuser \
    && install -d --owner=appuser --group=appuser --mode=0750 /app/data

# Allowlist runtime code and the immutable graph snapshot.  Do not replace
# these copies with `COPY . .`: .dockerignore and this list are both security
# boundaries against credentials and mutable case evidence entering an image.
COPY --chown=appuser:appuser run_analyst_pipeline.py assessment_template_consolidated.md ./
COPY --chown=appuser:appuser mitre_nodes.csv mitre_edges.csv zig_nodes.csv zig_edges.csv cref_nodes.csv cref_edges.csv ./
# `COPY --chown` intentionally preserves source modes.  The manifests may be
# created with 0600 on the build host, while Compose runs as the host-mapped
# non-root UID rather than appuser; make immutable graph metadata readable
# without broadening permissions on the writable /app/data mount.
COPY --chown=appuser:appuser --chmod=0644 graph_embeddings.npz embedding_metadata.json graph_snapshot_manifest.json ./
COPY --chown=appuser:appuser scripts/ ./scripts/
COPY --chown=appuser:appuser webapp/backend/main.py webapp/backend/auth.py webapp/backend/db.py webapp/backend/legacy_import.py webapp/backend/maintenance.py webapp/backend/pipeline_adapter.py webapp/backend/pdf_export.py webapp/backend/validation.py webapp/backend/workspace.py ./webapp/backend/

# Frontend build output is the only frontend content in the runtime image.
COPY --chown=appuser:appuser --from=frontend-build /build/webapp/frontend/dist ./webapp/frontend/dist

USER 10001:10001
EXPOSE 8000

# A single Uvicorn process owns the bounded in-process worker executor.  The
# shell sets a private umask so workspace evidence and generated reports are
# not world-readable even when a deployment does not override it.
CMD ["sh", "-c", "umask 077 && exec uvicorn webapp.backend.main:app --host 0.0.0.0 --port 8000 --workers 1"]
