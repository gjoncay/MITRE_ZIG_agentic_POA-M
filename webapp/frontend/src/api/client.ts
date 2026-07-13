import type {
  AnalyzeResponse,
  DeleteReportResult,
  JobEvent,
  JobStatusResponse,
  Provider,
  ReportDetail,
  ReportFilters,
  ReportListPage,
  ReportRevision,
  ReportSummary,
  ReviewDecision,
  RunListPage,
  RunSnapshot,
} from "../types";

const API_ROOT = "/api";
const SESSION_TOKEN_STORAGE_KEY = "csdh-api-session-bootstrap";

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : value == null ? fallback : String(value);
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => asString(item)).filter(Boolean) : [];
}

function asProgress(value: unknown): RunSnapshot["progress"] {
  const record = asRecord(value);
  const result: RunSnapshot["progress"] = {};
  for (const [key, raw] of Object.entries(record)) {
    if (typeof raw === "number" && Number.isFinite(raw)) result[key] = raw;
  }
  return result;
}

async function parseJsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = "";
    try {
      const body: unknown = await res.json();
      const record = asRecord(body);
      detail = asString(record.detail || record.error || record.message);
      if (!detail) detail = JSON.stringify(body);
    } catch {
      detail = await res.text().catch(() => "");
    }
    throw new ApiError(detail || `Request failed with status ${res.status}`, res.status);
  }
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError("The server returned an invalid JSON response.", res.status);
  }
}

function withBrowserAuth(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  const bootstrapToken = window.sessionStorage.getItem(SESSION_TOKEN_STORAGE_KEY);
  if (bootstrapToken && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${bootstrapToken}`);
  return { ...init, headers, credentials: "same-origin" };
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_ROOT}${path}`, withBrowserAuth(init));
  return parseJsonOrThrow<T>(res);
}

function isMissingRoute(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 405);
}

function makeForm(args: AnalyzeArgs): FormData {
  const form = new FormData();
  if (args.file) form.append("file", args.file);
  else if (args.text) form.append("text", args.text);
  if (args.provider) form.append("provider", args.provider);
  if (args.model?.trim()) form.append("model", args.model.trim());
  return form;
}

function normalizeRun(raw: unknown): RunSnapshot {
  const item = asRecord(raw);
  const counters = asRecord(item.counters);
  const progress = asProgress(item.progress ?? counters);
  const id = asString(item.id || item.run_id || item.job_id);
  return {
    id,
    status: asString(item.status, "queued"),
    stage: asString(item.stage || item.current_stage || item.phase, "Queued"),
    error: item.error == null && item.error_message == null ? null : asString(item.error ?? item.error_message),
    report_ids: asStringArray(item.report_ids || item.reports),
    created_at: asString(item.created_at || item.created, "") || undefined,
    started_at: asString(item.started_at || item.started, "") || undefined,
    generation_finished_at: asString(item.generation_finished_at, "") || undefined,
    finished_at: asString(item.finished_at || item.finished, "") || undefined,
    requested_provider: asString(item.requested_provider || item.provider, "") || undefined,
    effective_provider: asString(item.effective_provider, "") || undefined,
    model: asString(item.model || item.effective_model || item.requested_model, "") || undefined,
    degraded_reason: item.degraded_reason == null ? null : asString(item.degraded_reason),
    review_required: Boolean(item.review_required || item.requires_review),
    review_gate: item.review_gate == null ? null : asString(item.review_gate),
    cancel_requested: Boolean(item.cancel_requested),
    progress,
    metrics: asProgress(item.metrics),
    version: (typeof item.version === "number" || typeof item.version === "string") ? item.version : undefined,
  };
}

function normalizeSeverity(value: unknown): Record<string, number> {
  const record = asRecord(value);
  const result: Record<string, number> = {};
  for (const [key, raw] of Object.entries(record)) result[key] = asNumber(raw);
  return result;
}

export function normalizeReportSummary(raw: unknown): ReportSummary {
  const item = asRecord(raw);
  const nestedTechnique = asRecord(item.technique);
  const id = asString(item.id || item.report_id || item.uuid);
  const reportId = asString(item.report_id || item.display_id || id, id);
  const qa = asString(item.qa_verdict || item.qa_state || item.verdict, "PENDING");
  const lifecycle = asString(item.lifecycle_state || item.status || item.state, qa === "PASS" ? "auto_passed" : qa === "FLAG" ? "auto_flagged" : "draft");
  const reviewState = asString(item.review_state || item.review_status, "") || undefined;
  const requiresReview =
    typeof item.requires_review === "boolean"
      ? item.requires_review
      : ["auto_flagged", "manual_review_required", "needs_rework", "mapping_validated", "qa_pending", "draft", "deleting", "restoring", "rejected"].includes(lifecycle)
        || qa === "FLAG"
        || ["pending", "required", "flagged", "rejected"].includes(reviewState ?? "");

  return {
    id,
    report_id: reportId,
    run_id: asString(item.run_id, "") || undefined,
    display_id: asString(item.display_id || item.aggregate_key, "") || undefined,
    technique_id: asString(item.technique_id || nestedTechnique.id || item.attack_id, "Unknown"),
    technique_name: asString(item.technique_name || nestedTechnique.name || item.title, "Untitled report"),
    finding_count: asNumber(item.finding_count || item.observation_count || item.findings_count),
    severity_breakdown: normalizeSeverity(item.severity_breakdown),
    qa_verdict: qa,
    lifecycle_state: lifecycle,
    review_state: reviewState,
    generated_date: asString(item.generated_date || item.created_at || item.created, ""),
    updated_at: asString(item.updated_at, "") || undefined,
    current_revision_id: asString(item.current_revision_id, "") || undefined,
    current_revision_number: asNumber(item.current_revision_number || item.revision_number, 0) || undefined,
    version: (typeof item.version === "number" || typeof item.version === "string") ? item.version : undefined,
    requires_review: requiresReview,
    provider: asString(item.provider || item.effective_provider, "") || undefined,
  };
}

function normalizeRevision(raw: unknown, fallbackNumber = 1): ReportRevision {
  const value = asRecord(raw);
  const data = isRecord(value.data) ? value.data : isRecord(value.json) ? value.json : undefined;
  return {
    ...value,
    id: asString(value.id || value.revision_id || value.uuid, `revision-${fallbackNumber}`),
    number: asNumber(value.number || value.revision_number || value.version, fallbackNumber),
    created_at: asString(value.created_at || value.generated_date, "") || undefined,
    state: asString(value.state || value.lifecycle_state, "") || undefined,
    qa_verdict: asString(value.qa_verdict || value.qa_state, "") || undefined,
    review_state: asString(value.review_state || value.review_status, "") || undefined,
    markdown: asString(value.markdown || value.content_markdown, "") || undefined,
    data,
    mapping_snapshot_hash: asString(value.mapping_snapshot_hash, "") || undefined,
    author: asString(value.author || value.created_by, "") || undefined,
  };
}

function normalizeReportDetail(raw: unknown): ReportDetail {
  const item = asRecord(raw);
  const base = normalizeReportSummary(item);
  const revisionItems = Array.isArray(item.revisions) ? item.revisions : [];
  const currentRaw = item.current_revision ?? item.revision;
  const revisions = revisionItems.map((revision, index) => normalizeRevision(revision, index + 1));
  const currentRevision = currentRaw ? normalizeRevision(currentRaw, revisions.length || 1) : revisions[0];
  const data = isRecord(item.data) ? item.data : isRecord(item.json) ? item.json : undefined;
  return {
    ...item,
    ...base,
    current_revision: currentRevision,
    revisions,
    markdown: asString(item.markdown || item.content_markdown, "") || currentRevision?.markdown,
    data,
    mappings: item.mappings,
    framework_mappings: item.framework_mappings,
    evidence: item.evidence,
    provenance: item.provenance,
    review_history: item.review_history,
  };
}

function queryString(values: Record<string, string | number | boolean | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  const result = params.toString();
  return result ? `?${result}` : "";
}

export interface AnalyzeArgs {
  text?: string;
  file?: File;
  provider?: Provider;
  /** A model identifier returned by the server's configured local endpoint. */
  model?: string;
}

export interface LocalModelsResponse {
  provider: "local";
  configured: boolean;
  models: string[];
  source: "openai_compatible" | "ollama" | null;
  error: string | null;
}

export interface BulkReviewResult {
  run: RunSnapshot;
  approvedCount: number;
}

export interface BrowserSession {
  actor: string;
  roles: string[];
  authenticationMode: string;
}

function normalizeBrowserSession(raw: unknown): BrowserSession {
  const item = asRecord(raw);
  return {
    actor: asString(item.actor, "authenticated user"),
    roles: asStringArray(item.roles),
    authenticationMode: asString(item.authentication_mode, "unknown"),
  };
}

/** Establish an HttpOnly, same-origin browser session for SSE and API calls.
 * The optional token remains only in session storage until the server accepts
 * it and sets the cookie; it is never put in a URL or local storage. */
export async function establishBrowserSession(token?: string): Promise<BrowserSession> {
  if (token?.trim()) window.sessionStorage.setItem(SESSION_TOKEN_STORAGE_KEY, token.trim());
  try {
    const raw = await requestJson<unknown>("/session", { method: "POST" });
    window.sessionStorage.removeItem(SESSION_TOKEN_STORAGE_KEY);
    return normalizeBrowserSession(raw);
  } catch (error) {
    // Leave the bootstrap token only for this browser tab so callers can
    // correct a transient connection failure without retyping it. It is
    // cleared when the tab/session closes, never persisted in local storage.
    throw error;
  }
}

/** Read the identity from the current authenticated server session.
 *
 * Privileged report actions send this actor back only because the durable API
 * keeps it as an explicit audit field.  The server remains authoritative and
 * rejects a mismatch, so callers must refresh rather than reuse browser-local
 * identity text from a previous login.
 */
export async function getBrowserSession(): Promise<BrowserSession> {
  return normalizeBrowserSession(await requestJson<unknown>("/session"));
}

/** Backward-compatible name for callers that need the live server identity. */
export async function refreshBrowserSession(): Promise<BrowserSession> {
  return getBrowserSession();
}

/**
 * Discover models from the operator-configured local endpoint.  The browser
 * never supplies an endpoint URL or sees an API key; this is strictly a
 * server-side inventory of the configured local service.
 */
export async function getLocalModels(): Promise<LocalModelsResponse> {
  const raw = await requestJson<unknown>("/local-models");
  const item = asRecord(raw);
  const source = asString(item.source);
  return {
    provider: "local",
    configured: Boolean(item.configured),
    models: asStringArray(item.models),
    source: source === "openai_compatible" || source === "ollama" ? source : null,
    error: item.error == null ? null : asString(item.error),
  };
}

/** POST /api/runs.  Older deployments receive a compatibility request to /api/analyze. */
export async function createRun(args: AnalyzeArgs): Promise<RunSnapshot> {
  try {
    const raw = await requestJson<unknown>("/runs", { method: "POST", body: makeForm(args) });
    return normalizeRun(raw);
  } catch (error) {
    if (!isMissingRoute(error)) throw error;
    const raw = await requestJson<AnalyzeResponse>("/analyze", { method: "POST", body: makeForm(args) });
    return normalizeRun({ id: raw.job_id, status: "queued", stage: "Starting analysis", report_ids: [] });
  }
}

/** Retained for callers outside the updated input screen. */
export async function analyze(args: AnalyzeArgs): Promise<AnalyzeResponse> {
  const run = await createRun(args);
  return { job_id: run.id };
}

/** GET /api/runs using the backend's page/page_size offset contract. */
export async function listRuns(filters: { status?: string; search?: string; page?: number; pageSize?: number } = {}): Promise<RunListPage> {
  const raw = await requestJson<unknown>(`/runs${queryString({
    status: filters.status,
    search: filters.search,
    page: filters.page,
    page_size: filters.pageSize,
  })}`);
  if (Array.isArray(raw)) {
    return {
      items: raw.map(normalizeRun),
      total: raw.length,
      page: filters.page ?? 1,
      page_size: filters.pageSize ?? raw.length,
    };
  }
  const record = asRecord(raw);
  const values = Array.isArray(record.items) ? record.items : Array.isArray(record.runs) ? record.runs : [];
  return {
    items: values.map(normalizeRun),
    total: typeof record.total === "number" ? record.total : values.length,
    page: asNumber(record.page, filters.page ?? 1),
    page_size: asNumber(record.page_size, filters.pageSize ?? values.length),
  };
}

/** GET /api/runs/{id}; falls back to the existing in-memory job endpoint during rollout. */
export async function getRun(runId: string): Promise<RunSnapshot> {
  try {
    const raw = await requestJson<unknown>(`/runs/${encodeURIComponent(runId)}`);
    return normalizeRun(raw);
  } catch (error) {
    if (!isMissingRoute(error)) throw error;
    const raw = await requestJson<JobStatusResponse>(`/jobs/${encodeURIComponent(runId)}`);
    return normalizeRun({ ...raw, id: runId });
  }
}

/** Compatibility alias used by older integrations. */
export async function getJobStatus(jobId: string): Promise<JobStatusResponse> {
  const run = await getRun(jobId);
  return { status: run.status, stage: run.stage, error: run.error, report_ids: run.report_ids, progress: run.progress };
}

export async function cancelRun(runId: string, version?: string | number): Promise<RunSnapshot> {
  const raw = await requestJson<unknown>(`/runs/${encodeURIComponent(runId)}/cancel`, {
    method: "POST",
    headers: version === undefined ? undefined : { "If-Match": String(version) },
  });
  return normalizeRun(raw);
}

/** Create an isolated retry run from the retained immutable source artifact. */
/** Retry a retained source artifact using the local provider only. */
export async function retryRun(runId: string, model?: string): Promise<RunSnapshot> {
  const raw = await requestJson<unknown>(`/runs/${encodeURIComponent(runId)}/retry`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(model?.trim() ? { model: model.trim() } : {}),
  });
  return normalizeRun(raw);
}

/**
 * Approve every report that is currently review-pending in one run.
 *
 * The backend writes an individual review decision for each report and uses
 * the server-derived actor.  A run version is required so a stale browser
 * cannot accidentally approve reports that appeared after the confirmation.
 */
export async function approveRunReviewPendingReports(
  runId: string,
  args: { reason: string; version?: string | number },
): Promise<BulkReviewResult> {
  const raw = await requestJson<unknown>(`/runs/${encodeURIComponent(runId)}/review-pending/approve`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(args.version === undefined ? {} : { "If-Match": String(args.version) }),
    },
    body: JSON.stringify({ reason: args.reason, version: args.version }),
  });
  const item = asRecord(raw);
  return {
    run: normalizeRun(item.run ?? item),
    approvedCount: asNumber(item.approved_count),
  };
}

/** URL used by EventSource.  Last-Event-ID is automatically managed by the browser after reconnect. */
export function getRunEventsUrl(runId: string): string {
  return `${API_ROOT}/runs/${encodeURIComponent(runId)}/events`;
}

export function normalizeJobEvent(raw: unknown): JobEvent {
  const item = asRecord(raw);
  // Durable SSE rows place the event fields at the top level.  Legacy
  // deployments may nest them under payload/data.  Preserve the direct form
  // too, so live counters and metrics update before the next REST poll.
  const payload = isRecord(item.payload) ? item.payload : isRecord(item.data) ? item.data : item;
  return {
    id: asString(item.id || item.event_id, "") || undefined,
    sequence: asNumber(item.sequence || item.seq, 0) || undefined,
    timestamp: asString(item.timestamp || item.created_at || item.at, "") || undefined,
    type: asString(item.type || item.event_type, "progress"),
    stage: asString(item.stage || item.phase, "") || undefined,
    message: asString(item.message || item.detail, "") || undefined,
    status: asString(item.status, "") || undefined,
    payload,
  };
}

/** GET /api/reports with the backend's page/page_size offset contract. */
export async function listReports(filters: ReportFilters = {}): Promise<ReportListPage> {
  const raw = await requestJson<unknown>(`/reports${queryString({
    run_id: filters.runId,
    search: filters.search,
    lifecycle_state: filters.lifecycleState,
    review_state: filters.reviewState,
    qa_verdict: filters.qaVerdict,
    include_deleted: filters.includeDeleted,
    page: filters.page,
    page_size: filters.pageSize,
  })}`);
  if (Array.isArray(raw)) {
    return {
      items: raw.map(normalizeReportSummary),
      total: raw.length,
      page: filters.page ?? 1,
      page_size: filters.pageSize ?? raw.length,
    };
  }
  const record = asRecord(raw);
  const values = Array.isArray(record.items) ? record.items : Array.isArray(record.reports) ? record.reports : [];
  return {
    items: values.map(normalizeReportSummary),
    total: typeof record.total === "number" ? record.total : values.length,
    page: asNumber(record.page, filters.page ?? 1),
    page_size: asNumber(record.page_size, filters.pageSize ?? values.length),
  };
}

/** GET /api/reports/{id}. */
export async function getReport(reportId: string): Promise<ReportDetail> {
  const raw = await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}`);
  return normalizeReportDetail(raw);
}

/** GET immutable revision data. */
export async function getReportRevision(reportId: string, revisionId: string): Promise<ReportRevision> {
  const raw = await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}/revisions/${encodeURIComponent(revisionId)}`);
  const record = asRecord(raw);
  return normalizeRevision(record.current_revision ?? record.revision ?? raw);
}

/** GET /api/reports/{id}/markdown. */
export async function getReportMarkdown(reportId: string): Promise<string> {
  const res = await fetch(`${API_ROOT}/reports/${encodeURIComponent(reportId)}/markdown`, withBrowserAuth());
  if (!res.ok) throw new ApiError(`Failed to load report markdown (status ${res.status})`, res.status);
  return res.text();
}

/** POST /api/reports/{id}/pdf — returns a report-revision specific PDF blob. */
export async function fetchReportPdf(reportId: string): Promise<Blob> {
  const res = await fetch(`${API_ROOT}/reports/${encodeURIComponent(reportId)}/pdf`, withBrowserAuth({ method: "POST" }));
  if (!res.ok) throw new ApiError(`Failed to generate PDF (status ${res.status})`, res.status);
  return res.blob();
}

export async function reviewReport(
  reportId: string,
  args: { decision: ReviewDecision; note: string; actor: string; version?: string | number },
): Promise<ReportDetail> {
  await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}/review`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(args.version === undefined ? {} : { "If-Match": String(args.version) }),
    },
    body: JSON.stringify({ decision: args.decision, note: args.note, actor: args.actor, version: args.version }),
  });
  return getReport(reportId);
}

export async function deleteReport(
  reportId: string,
  args: { reason: string; actor: string; version?: string | number },
): Promise<DeleteReportResult> {
  const raw = await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}`, {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
      ...(args.version === undefined ? {} : { "If-Match": String(args.version) }),
    },
    body: JSON.stringify({ reason: args.reason, actor: args.actor, version: args.version }),
  });
  const item = asRecord(raw);
  const deletion = asRecord(item.deletion);
  const report = asRecord(item.report);
  return {
    report_id: asString(item.report_id || item.id || report.id, reportId),
    deleted: item.deleted === undefined ? true : Boolean(item.deleted),
    undo_expires_at: asString(item.undo_expires_at || deletion.undo_expires_at, "") || null,
    version: (typeof report.version === "number" || typeof report.version === "string") ? report.version : undefined,
  };
}

export async function restoreReport(reportId: string, args: { actor: string; reason?: string; version?: string | number }): Promise<ReportDetail> {
  await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}/restore`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(args.version === undefined ? {} : { "If-Match": String(args.version) }),
    },
    body: JSON.stringify(args),
  });
  return getReport(reportId);
}

/**
 * Create a current-template report revision from retained report data and the
 * current validated graph mappings.
 *
 * This deliberately has no provider/model options: the backend endpoint is a
 * graph-backed presentation refresh, not a source-run retry or a new LLM
 * request.
 */
export async function rerenderReport(reportId: string): Promise<ReportDetail> {
  await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}/rerender`, {
    method: "POST",
  });
  // Fetch the canonical detail after the mutation rather than coupling the UI
  // to a particular acknowledgement payload from the endpoint.
  return getReport(reportId);
}

/** Retry the entire retained source run that produced this report. */
export async function retrySourceRunForReport(reportId: string): Promise<RunSnapshot> {
  const raw = await requestJson<unknown>(`/reports/${encodeURIComponent(reportId)}/retry-source-run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  return normalizeRun(raw);
}

/** GET /api/health */
export async function getHealth(): Promise<{ status: string; graph_nodes: number; graph_edges: number }> {
  return requestJson("/health");
}
