# Web Deployment Operations Runbook

This runbook covers the local/Tailscale web application only. It does not apply
to the air-gapped CLI deployment described in
`Air_Gapped_Deployment_Guide.md`.

The web service is a single-host application. Its durable state is not kept in
the Git checkout or in the container filesystem: it lives in `./data` on the
host, mounted as `/app/data` in the application container.

## What must be protected

`data/` can contain submitted evidence, normalized observations, source hashes,
SQLite/WAL lifecycle data, report revisions, PDFs, and soft-delete trash. Treat
it as sensitive case material.

```text
data/
├── csdh.sqlite3             SQLite lifecycle/review database
├── csdh.sqlite3-wal         active write-ahead log while the service runs
├── csdh.sqlite3-shm         SQLite shared-memory sidecar while the service runs
└── runs/<run UUID>/
    ├── upload/              original submitted artifact or pasted text
    ├── normalized/          normalized observations.csv
    ├── mapping/             run-scoped mapping material
    ├── pipeline_output/     pipeline staging artifacts
    ├── reports/             immutable published Markdown/JSON/PDF assets
    ├── exports/             generated exports
    └── trash/               soft-deleted report assets during the undo window
```

Do not mount `reports/` or `webapp/backend/uploads/` into the web container.
Those are legacy paths; the durable web backend writes only below `data/runs`.
`data/` is excluded from Git and from the Docker build context.

## First deployment

1. Install Docker Engine and Docker Compose v2 on the host. Keep the repository
   itself on an encrypted, access-controlled disk where possible.
2. Create the private runtime directory before Compose can create it as root:

   ```bash
   mkdir -p data
   chmod 700 data
   ```

3. Copy the configuration template and protect it. Edit `APP_UID` and
   `APP_GID` to the numeric owner of `data/` (`id -u` and `id -g` on Linux).

   ```bash
   cp .env.example .env
   chmod 600 .env
   id -u
   id -g
   ```

   The application image has its own non-root account. Compose maps the running
   process to the host owner's UID/GID so the `./data` bind mount is writable
   without `chmod 777` or a root-owned database. After changing ownership or
   moving the checkout, verify it again with `stat -c '%u:%g %a' data`.

4. Set `TS_AUTHKEY`, configure web authentication, and choose a provider.
   Token mode is the production default: set `CSDH_AUTH_TOKENS_JSON` to a
   nonempty JSON token map with high-entropy secrets, server-derived actor IDs,
   and least-privilege roles. Alternatively use `CSDH_AUTH_MODE=trusted_proxy`
   only behind a proxy that authenticates every request and strips/replaces the
   configured identity and roles headers. `disabled` is development-only. The
   health endpoint stays degraded and protected API routes are unavailable
   until token configuration is valid. Leave `LLM_PROVIDER=none` unless a local
   or cloud model is intentionally enabled. A cloud provider causes submitted
   evidence to leave the host only after an explicit per-submission (and
   per-retry) acknowledgement in the UI/API; that acknowledgement is not a
   replacement for an organization’s data-handling approval.
5. Validate the resolved configuration, build, and start the stack:

   ```bash
   docker compose config --quiet
   docker compose build --pull
   docker compose up -d
   docker compose ps
   docker compose exec app python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5).read().decode())"
   ```

   The final request runs inside the application network namespace. The normal
   external verification path is the tailnet URL described in
   `TAILSCALE_SIDECAR.md`; there is intentionally no host `ports:` binding.

6. Confirm that the app did not start as root and that no host port was
   published:

   ```bash
   docker compose exec app id
   docker compose port app 8000 || true
   docker compose logs --tail=100 app app-ts
   ```

   The `id` output must not show `uid=0`. `docker compose port` should produce
   no binding; the Tailscale sidecar is the intended ingress.

## Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `APP_UID`, `APP_GID` | `1000` | Numeric Linux identity used for the `./data` bind mount. Set to the directory owner. |
| `TAILSCALE_IMAGE` | `tailscale/tailscale:v1.98` | Version-pinned sidecar image. Use a reviewed digest for a production promotion. |
| `CSDH_AUTH_MODE` | `token` | `token` (recommended), or `trusted_proxy` behind a correctly sanitizing authenticated proxy. `disabled` is local development only. |
| `CSDH_AUTH_TOKENS_JSON` | none | Required in token mode. JSON map from an unpredictable bearer token to `{"actor": ..., "roles": [...]}`. Never commit it. |
| `CSDH_TRUSTED_PROXY_USER_HEADER` | `X-CSDH-Authenticated-User` | Identity header injected only by the trusted reverse proxy; roles use the same header plus `-Roles`. |
| `CSDH_SESSION_COOKIE_SECURE` | `true` | Keeps the HttpOnly browser/SSE session cookie HTTPS-only. Do not disable for the Tailscale HTTPS service. |
| `LLM_PROVIDER` | `none` | `none`, `local`, `openai`, or `gemini`. `none` makes no model-network call. |
| `LOCAL_LLM_*` | see `.env.example` | OpenAI-compatible local endpoint, model, and optional key. In Compose use `host.docker.internal`, not `localhost`, for a host model server. |
| `OPENAI_*`, `GEMINI_*` | provider defaults | Cloud provider credentials/model names. Keep keys only in the protected `.env` or a managed secret mechanism. |
| `LLM_REQUEST_TIMEOUT_SECONDS` | `90` | Per-model request timeout, including each OpenAI-compatible or Gemini graph-planner request. This bounds the wait before the next cancellation checkpoint. |
| `LLM_GRAPH_TOOL_CRAWL` | `enabled` | Lets a non-heuristic provider make a bounded, read-only graph-tool crawl with per-request progress events. |
| `LLM_GRAPH_TOOL_MAX_CALLS` | `6` | Default maximum provider/tool-plan requests per report; implementation hard-caps it at 12. |
| `CSDH_MAX_UPLOAD_BYTES` | `26214400` | Maximum uploaded file size (25 MiB). |
| `CSDH_MAX_TEXT_CHARACTERS` | `2000000` | Maximum pasted-text size. |
| `CSDH_WORKER_CONCURRENCY` | `1` | Background analysis workers inside the one Uvicorn process. Raise only after capacity testing. |
| `CSDH_DELETE_RETENTION_HOURS` | `720` | Soft-delete undo/restore window (30 days). |

`CSDH_DATA_DIR` and `CSDH_DB_PATH` are deliberately fixed to `/app/data` by
Compose. For a direct, non-containerized web launch, set them to an absolute
private directory outside the source tree or to a protected local `data/`
directory; do not set them to an NFS/SMB share because SQLite/WAL requires
reliable local filesystem locking.

## Runtime security boundaries

- The application container runs as a non-root UID, has a read-only root
  filesystem, a private `/tmp` tmpfs, all Linux capabilities dropped, and
  `no-new-privileges` enabled. Its only writable persistent path is
  `/app/data`.
- The Docker build context is a strict allowlist. It contains runtime code, the
  graph snapshot, and frontend build inputs only. `.env`, Git history,
  uploads, reports, databases, raw source material, local venvs, and dependency
  directories do not enter the build context or image.
- Tailscale limits network reachability; it is not report-level authorization.
  Restrict tailnet membership/ACLs and configure application authentication.
  The server, not a request body, derives reviewer/deletion actor identities.
  Treat all submitted files and model output as untrusted.
- The Tailscale sidecar uses userspace networking and is the only intended
  ingress. Do not add `ports:` casually or expose Uvicorn directly to a LAN.
- If a host LLM is used, bind it only as broadly as needed and firewall its port
  to the Compose bridge subnet. A container’s `localhost` is not the host.

## Upgrade and graph-snapshot procedure

1. Let running analyses reach a terminal state or cancel them in the UI.
2. Create and verify a backup of `data/` as described below.
3. Review the source diff, dependency changes, base-image tags, and the
   graph-snapshot manifest. The immutable graph CSVs and embedding metadata are
   baked into the image; a graph update therefore requires an image rebuild.
4. Build and recreate both network-coupled services together:

   ```bash
   docker compose build --pull
   docker compose up -d --force-recreate app app-ts
   docker compose ps
   ```

   `app-ts` shares the application network namespace. Recreating only `app`
   can leave the sidecar attached to the old container identity.
5. Verify `/api/health`, a no-provider test submission, the run progress stream,
   and an approved/flagged report path before accepting new evidence.

The Dockerfile pins Node and Python to explicit patch tags, and Compose pins
Tailscale to a version tag. Before a regulated promotion, resolve the exact
multi-architecture manifest digest with your approved registry workflow (for
example `docker buildx imagetools inspect <image>`) and replace the tag/digest
after testing it in a staging host. Generate an SBOM and scan the resulting
image with the organization-approved scanner; Python requirements currently use
compatible minimum versions rather than a committed hash lock.

## Backup, restore, and retention

Back up the whole `data/` tree, not just `csdh.sqlite3`: report assets and
original artifacts live in run workspaces. Keep backups encrypted and with
permissions at least as restrictive as the live directory.

For the simplest consistent backup, perform a short planned quiescence while
no run is processing:

```bash
# Verify in the UI/API that no run is queued or running, then stop only the app.
docker compose stop app

stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p ../mitre-csdh-backups
chmod 700 ../mitre-csdh-backups
tar -C . -czf "../mitre-csdh-backups/mitre-csdh-data-${stamp}.tgz" data
sha256sum "../mitre-csdh-backups/mitre-csdh-data-${stamp}.tgz" \
  > "../mitre-csdh-backups/mitre-csdh-data-${stamp}.tgz.sha256"

docker compose start app
```

Stopping the app avoids copying an actively changing SQLite WAL or a partially
published workspace. The service stops intake, signals cooperative checkpoints,
and joins its workers before the container exits; allow at least one configured
model-request timeout for a graceful stop if a provider call is in flight.
Interrupted work is requeued and reset/replayed from its immutable upload on the
next healthy startup rather than merged with partial output. Test this procedure and a restore on a non-production
host before relying on it. Back up the `apptsdata` named volume separately only
if preserving the existing Tailscale node identity is required; it contains no
analysis reports.

To restore a complete data backup:

```bash
# Stop the service and preserve the failed state for investigation first.
docker compose stop app
mv data "data.before-restore-$(date -u +%Y%m%dT%H%M%SZ)"
tar -xzf ../mitre-csdh-backups/mitre-csdh-data-<timestamp>.tgz
chmod 700 data
# Ensure this owner matches APP_UID:APP_GID before starting the app again.
docker compose start app
```

After restoration, inspect `/api/health`, a historical run, a report revision,
and a PDF export. Do not copy a lone `csdh.sqlite3` over a live database while
its `-wal`/`-shm` sidecars exist; restore the coherent `data/` snapshot instead.

`CSDH_DELETE_RETENTION_HOURS` controls when a soft-deleted report can no longer
be restored. It does **not** by itself guarantee physical erasure of original
evidence or backups. Perform any purge only as an approved maintenance action
after the undo window, legal retention period, and backup policy have all been
reviewed.

## Incident and routine checks

- If the web app cannot write SQLite or workspaces, stop it, check
  `ls -ld data`, compare its owner to `APP_UID:APP_GID`, and correct ownership
  rather than weakening permissions to world-writable.
- If the sidecar becomes unreachable after an app rebuild, run
  `docker compose up -d --force-recreate app app-ts` and inspect
  `docker compose logs app-ts`.
- If a cloud provider was selected unexpectedly, stop accepting new artifacts,
  inspect the run’s requested/effective provider and audit events, rotate any
  exposed provider credential, and preserve the affected workspace for the
  incident process.
- If a restart occurs during analysis, inspect the durable `run_interrupted_for_shutdown`
  and `run_recovered` events after startup. The rerun should be a clean replay
  from the retained source artifact; it must not contain duplicate observations
  or a mixture of partial and replayed reports.
- `/api/health` includes `semantic_search`. A value beginning `ready` means a
  compatible local embedding model and snapshot-bound index were available;
  `degraded: ...` is the safe lexical fallback. The Docker image does not bake
  HuggingFace model weights by default, so lexical retrieval is expected unless
  an approved read-only local model cache is deliberately supplied.
- At least monthly: apply reviewed image/dependency updates, validate a backup
  restore, check free space under `data/`, review deleted-report trash, and
  confirm tailnet ACL membership.
