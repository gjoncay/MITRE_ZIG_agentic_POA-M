/** Shared frontend API shapes.  The backend intentionally returns rich JSON for
 * report mappings, so report detail keeps open-ended sections as unknown values. */

export type Provider = "" | "local" | "openai" | "gemini" | "none";

export type RunStatus =
  | "queued"
  | "pending"
  | "running"
  | "analysis_finished"
  | "awaiting_review"
  | "completed"
  | "done"
  | "failed"
  | "canceled"
  | "cancel_requested"
  | string;

export type ReportLifecycleState =
  | "draft"
  | "mapping_validated"
  | "qa_pending"
  | "auto_passed"
  | "auto_flagged"
  | "manual_review_required"
  | "approved"
  | "needs_rework"
  | "rejected"
  | "archived"
  | "deleted"
  | "legacy"
  | string;

export type ReviewDecision = "approve" | "needs_rework" | "reject" | "waive";

export interface AnalyzeResponse {
  job_id: string;
}

export interface ProgressMetrics {
  artifacts_total?: number;
  artifacts_completed?: number;
  observations_total?: number;
  observations_completed?: number;
  techniques_total?: number;
  techniques_completed?: number;
  reports_total?: number;
  reports_completed?: number;
  reports_auto_passed?: number;
  reports_flagged?: number;
  reports_review_pending?: number;
  errors?: number;
  retries?: number;
  [key: string]: number | undefined;
}

export interface RunSnapshot {
  id: string;
  status: RunStatus;
  stage: string;
  error: string | null;
  report_ids: string[];
  created_at?: string;
  started_at?: string;
  generation_finished_at?: string;
  finished_at?: string;
  requested_provider?: string;
  effective_provider?: string;
  model?: string;
  degraded_reason?: string | null;
  review_required?: boolean;
  review_gate?: string | null;
  retry_provider?: string;
  retry_requires_cloud_acknowledgement?: boolean;
  cancel_requested?: boolean;
  progress: ProgressMetrics;
  metrics?: ProgressMetrics;
  version?: string | number;
}

/** Legacy endpoint compatibility while installations transition to /api/runs. */
export interface JobStatusResponse {
  status: RunStatus;
  stage: string;
  error: string | null;
  report_ids: string[];
  progress?: ProgressMetrics;
}

export interface RunListPage {
  items: RunSnapshot[];
  total?: number;
  page?: number;
  page_size?: number;
}

export interface JobEvent {
  id?: string;
  sequence?: number;
  timestamp?: string;
  type: string;
  stage?: string;
  message?: string;
  status?: RunStatus;
  payload?: Record<string, unknown>;
}

export interface ReportSummary {
  /** Stable report UUID in the durable API; report_id remains for legacy payloads. */
  id: string;
  report_id: string;
  run_id?: string;
  display_id?: string;
  technique_id: string;
  technique_name: string;
  finding_count: number;
  severity_breakdown: Record<string, number>;
  qa_verdict: "PASS" | "FLAG" | "PENDING" | string;
  lifecycle_state: ReportLifecycleState;
  review_state?: string;
  generated_date: string;
  updated_at?: string;
  current_revision_id?: string;
  current_revision_number?: number;
  version?: string | number;
  requires_review?: boolean;
  provider?: string;
}

export interface ReportRevision {
  id: string;
  number: number;
  created_at?: string;
  state?: string;
  qa_verdict?: string;
  review_state?: string;
  markdown?: string;
  data?: Record<string, unknown>;
  mapping_snapshot_hash?: string;
  author?: string;
  [key: string]: unknown;
}

export interface ReportDetail extends ReportSummary {
  current_revision?: ReportRevision;
  revisions: ReportRevision[];
  markdown?: string;
  data?: Record<string, unknown>;
  mappings?: unknown;
  framework_mappings?: unknown;
  evidence?: unknown;
  provenance?: unknown;
  review_history?: unknown;
  [key: string]: unknown;
}

export interface ReportListPage {
  items: ReportSummary[];
  total?: number;
  page?: number;
  page_size?: number;
}

export interface ReportFilters {
  runId?: string;
  search?: string;
  lifecycleState?: string;
  reviewState?: string;
  qaVerdict?: string;
  includeDeleted?: boolean;
  page?: number;
  pageSize?: number;
}

export interface DeleteReportResult {
  report_id: string;
  deleted: boolean;
  undo_expires_at?: string | null;
  version?: string | number;
}
