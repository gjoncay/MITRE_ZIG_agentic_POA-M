"""
webapp/backend/main.py

FastAPI backend for the MITRE CSD-H analyst-report web UI. Implements the
fixed API contract (see project brief) that the React frontend (webapp/
frontend/) and the PDF renderer (pdf_export.py) are being built against in
parallel -- paths/methods/response shapes here must not drift from that
contract.

Concurrency model: job tracking uses a plain in-memory dict (JOBS), not a
database or external queue. This is an intentional simplicity tradeoff for a
single-user local/Tailscale tool, but it means the dict is NOT shared across
processes. Run uvicorn with EXACTLY ONE worker (no --workers >1, and don't
front this with multiple gunicorn workers) or job status lookups will miss
jobs created by a different worker.
"""
import asyncio
import glob
import json
import logging
import os
import sys
import uuid

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre_csdh.webapp")

# ---------------------------------------------------------------------------
# Path setup. main.py lives at <repo_root>/webapp/backend/main.py, so three
# dirname() calls get back to <repo_root>. The pipeline/graph modules assume
# they're launched from (or given absolute paths rooted at) the repo root, so
# we chdir there too -- ingest_assessment.ingest_file() in particular writes
# its output to a hardcoded relative "processed_assessment.csv" path with no
# parameter to override it, so the process cwd has to be the repo root for
# that file to land somewhere predictable.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BACKEND_DIR, "uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
INPUT_CSV = os.path.join(BASE_DIR, "processed_assessment.csv")
FRONTEND_DIST = os.path.join(BASE_DIR, "webapp", "frontend", "dist")

os.chdir(BASE_DIR)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, BACKEND_DIR)  # so `from pdf_export import ...` resolves regardless of launch cwd

from graph_engine import KnowledgeGraphEngine  # noqa: E402
from ingest_assessment import ingest_file, ingest_text  # noqa: E402
from run_analyst_pipeline import run_pipeline  # noqa: E402

# ---------------------------------------------------------------------------
# Globals: one KnowledgeGraphEngine for the whole process lifetime (built at
# startup -- never per-request, since loading ~5600 nodes + vectors is slow),
# and the in-memory job store described in the module docstring.
# ---------------------------------------------------------------------------
engine: KnowledgeGraphEngine | None = None
JOBS: dict[str, dict] = {}

VALID_PROVIDERS = {"local", "openai", "gemini", "none"}
VALID_REPORT_ID_RE_MSG = "report_id must not contain path separators"


def _valid_report_id(report_id: str) -> bool:
    """Path-traversal guard: report_id is used directly to build filesystem
    paths under REPORTS_DIR, so reject anything that isn't a bare filename
    component (e.g. '..', '/etc/passwd', 'a/../../b')."""
    return bool(report_id) and os.path.basename(report_id) == report_id and report_id not in (".", "..")


async def lifespan(app: FastAPI):
    global engine
    logger.info("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()
    yield


app = FastAPI(title="MITRE CSD-H Analyst Pipeline API", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Background job runner
# ---------------------------------------------------------------------------
def _run_job(job_id: str, saved_upload_path: str | None, text: str | None, provider_name: str | None):
    job = JOBS[job_id]
    try:
        job["status"] = "running"

        def progress_cb(stage: str):
            job["stage"] = stage

        if saved_upload_path is not None:
            ingest_file(saved_upload_path)
        else:
            ingest_text(text, output_csv=INPUT_CSV)

        results = run_pipeline(
            engine,
            INPUT_CSV,
            REPORTS_DIR,
            provider_name=provider_name,
            progress_cb=progress_cb,
        )

        job["report_ids"] = [r["report_id"] for r in results]
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001 -- must never leave a job stuck at "running"
        logger.exception("Job %s failed", job_id)
        job["status"] = "failed"
        job["error"] = str(exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
async def analyze(
    file: UploadFile | None = File(None),
    text: str | None = Form(None),
    provider: str | None = Form(None),
):
    """Starts a background analyst-report job from either an uploaded file or
    pasted text. Judgment call: the contract says "EITHER a file field OR a
    text field" but doesn't specify what happens if both or neither are sent.
    We treat "file" as taking priority if both are present (matches the
    frontend client, which only ever sends one), and 400 if neither is
    present or if "text" is present but empty/whitespace-only."""
    if file is None and (text is None or not text.strip()):
        raise HTTPException(status_code=400, detail="Provide either a 'file' or a non-empty 'text' field.")

    if provider is not None and provider not in VALID_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider '{provider}'. Must be one of {sorted(VALID_PROVIDERS)}.",
        )
    # "none" means "use LLM_PROVIDER env var default" in the same way that
    # omitting the field does -- run_pipeline/get_provider treat None the
    # same as an unrecognized/empty name (heuristic fallback), so normalize
    # "none" to None here rather than threading the literal string through.
    provider_name = None if provider in (None, "", "none") else provider

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"status": "pending", "stage": "", "error": None, "report_ids": []}

    saved_upload_path = None
    text_payload = None
    if file is not None:
        safe_name = os.path.basename(file.filename or "upload")
        saved_upload_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_name}")
        contents = await file.read()
        with open(saved_upload_path, "wb") as f:
            f.write(contents)
        os.chmod(saved_upload_path, 0o666)  # host-editable bind mount; see run_analyst_pipeline.py chmod comment
    else:
        text_payload = text

    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, _run_job, job_id, saved_upload_path, text_payload, provider_name)

    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No job with id '{job_id}'.")
    return {
        "status": job["status"],
        "stage": job["stage"],
        "error": job["error"],
        "report_ids": job["report_ids"],
    }


def _report_summary_from_json(data: dict) -> dict:
    return {
        "report_id": data.get("report_id"),
        "technique_id": data.get("technique_id"),
        "technique_name": data.get("technique_name"),
        "finding_count": data.get("finding_count"),
        "severity_breakdown": data.get("severity_breakdown"),
        "qa_verdict": data.get("qa_verdict"),
        "generated_date": data.get("generated_date"),
    }


@app.get("/api/reports")
async def list_reports():
    """Scans reports/*.json on disk (not an in-memory list) so reports from
    earlier CLI runs (or a previous server process) show up too."""
    summaries = []
    for path in sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping unreadable report %s: %s", path, exc)
            continue
        summaries.append(_report_summary_from_json(data))
    return summaries


@app.get("/api/reports/{report_id}")
async def get_report(report_id: str):
    if not _valid_report_id(report_id):
        raise HTTPException(status_code=400, detail=VALID_REPORT_ID_RE_MSG)
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@app.get("/api/reports/{report_id}/markdown")
async def get_report_markdown(report_id: str):
    if not _valid_report_id(report_id):
        raise HTTPException(status_code=400, detail=VALID_REPORT_ID_RE_MSG)
    path = os.path.join(REPORTS_DIR, f"{report_id}.md")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    return PlainTextResponse(content=text, media_type="text/markdown")


@app.post("/api/reports/{report_id}/pdf")
async def get_report_pdf(report_id: str):
    if not _valid_report_id(report_id):
        raise HTTPException(status_code=400, detail=VALID_REPORT_ID_RE_MSG)

    md_path = os.path.join(REPORTS_DIR, f"{report_id}.md")
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")

    if not os.path.isfile(md_path):
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    # Cache freshness: only regenerate if there's no cached PDF, or the
    # markdown has been rewritten more recently than the cached PDF.
    if os.path.isfile(pdf_path) and os.path.getmtime(pdf_path) >= os.path.getmtime(md_path):
        with open(pdf_path, "rb") as f:
            return Response(content=f.read(), media_type="application/pdf")

    try:
        from pdf_export import render_report_pdf
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF export is not available yet: webapp/backend/pdf_export.py is missing or its "
                   "dependencies (e.g. weasyprint) are not installed.",
        )

    try:
        pdf_bytes = render_report_pdf(report_id, REPORTS_DIR)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    os.chmod(pdf_path, 0o666)  # host-editable bind mount; see run_analyst_pipeline.py chmod comment

    return Response(content=pdf_bytes, media_type="application/pdf")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "graph_nodes": engine.graph.number_of_nodes(),
        "graph_edges": engine.graph.number_of_edges(),
    }


# ---------------------------------------------------------------------------
# Static frontend. The built React app (webapp/frontend/dist/) may not exist
# yet -- e.g. during standalone backend testing, or before the frontend build
# has run in CI/Docker -- so this is guarded rather than assumed.
# ---------------------------------------------------------------------------
if os.path.isdir(FRONTEND_DIST):
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
else:
    logger.warning("Frontend build not found at %s; skipping StaticFiles mount (API routes still work).", FRONTEND_DIST)
