# MITRE CSD-H web UI — multi-stage build (React frontend + FastAPI backend).
# See ./TAILSCALE_SIDECAR.md for how this container is exposed on the tailnet.
#
# NOTE: at the time this Dockerfile was written, webapp/backend/ was still
# being authored by a parallel task. It targets the FastAPI app variable at
# webapp/backend/main.py:app (module path webapp.backend.main:app) and a
# single uvicorn worker, per that module's in-memory job-store constraint. If
# the backend agent named things differently, update the CMD below to match.

# ---- Stage 1: build the React frontend ----
FROM node:20-slim AS frontend-build
WORKDIR /app/webapp/frontend
COPY webapp/frontend/package*.json ./
# No package-lock.json exists yet in this repo -> npm install (switch to
# `npm ci` once a lockfile is committed).
RUN npm install
COPY webapp/frontend/ ./
RUN npm run build

# ---- Stage 2: Python backend + graph engine, serving the built frontend ----
FROM python:3.14-slim AS final

# System packages required by weasyprint (PDF export) — see
# webapp/backend/pdf_export.py for the authoritative list if it documents
# more; this is the set called out in the build spec:
# NOTE: python:3.14-slim is Debian trixie (13), which renamed
# libgdk-pixbuf2.0-0 -> libgdk-pixbuf-2.0-0. If the base image moves to an
# older Debian release, you may need the old name instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring in the whole repo: graph CSVs, scripts/, webapp/backend/, templates,
# requirements files, skill docs, etc.
COPY . .

# Frontend build output -> served by the backend as static files.
COPY --from=frontend-build /app/webapp/frontend/dist ./webapp/frontend/dist

# Base graph/pipeline deps (Tier 1-4, incl. optional semantic-search stack:
# numpy/scikit-learn/sentence-transformers/torch) + additive web-layer deps.
# Model weights for sentence-transformers are NOT baked in here — downloaded
# at runtime on first use, kept out of the image/build.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r webapp/backend/requirements.txt

EXPOSE 8000

# Exactly one worker — webapp/backend/main.py's job store is in-memory and
# not safe to share across multiple worker processes.
CMD ["uvicorn", "webapp.backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
