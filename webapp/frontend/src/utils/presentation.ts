import type { ProgressMetrics, ReportSummary, RunSnapshot } from "../types";

export function formatDate(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

export function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  const seconds = Math.round(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

export function titleCase(value?: string): string {
  if (!value) return "Unknown";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function isTerminalRun(status: string): boolean {
  return ["completed", "done", "failed", "canceled"].includes(status);
}

export function runNeedsReview(run: RunSnapshot): boolean {
  // `reports_flagged` is a historical count, not an actionable count. A run
  // that began with flagged reports must become complete after every one has
  // an accepted review decision; otherwise the bulk-review action would leave
  // the UI permanently warning even though the durable completion gate passed.
  if (["completed", "done"].includes(run.status)) return false;
  if (run.status === "awaiting_review") return true;
  if (typeof run.progress.reports_review_pending === "number") return run.progress.reports_review_pending > 0;
  // Older deployments may not supply the explicit pending counter. Retain a
  // narrow compatibility fallback for those snapshots only.
  return Boolean(run.review_required) || (run.progress.reports_flagged ?? 0) > 0;
}

export function reportNeedsReview(report: ReportSummary): boolean {
  // A rejection is recorded in the immutable audit history but is not a pass.
  // It remains actionable as rework until the run has an accepted outcome.
  if (["approved", "auto_passed", "waived", "deleted", "legacy"].includes(report.lifecycle_state)) return false;
  return Boolean(report.requires_review)
    || ["auto_flagged", "manual_review_required", "needs_rework", "mapping_validated", "qa_pending", "draft", "deleting", "restoring", "rejected"].includes(report.lifecycle_state)
    || ["pending", "required", "flagged", "rejected"].includes(report.review_state ?? "");
}

export function getProgressPair(progress: ProgressMetrics): { completed: number; total: number; label: string } {
  const candidates: Array<[keyof ProgressMetrics, keyof ProgressMetrics, string]> = [
    ["reports_completed", "reports_total", "reports"],
    ["techniques_completed", "techniques_total", "techniques"],
    ["observations_completed", "observations_total", "observations"],
    ["artifacts_completed", "artifacts_total", "artifacts"],
  ];
  for (const [completeKey, totalKey, label] of candidates) {
    const completed = progress[completeKey];
    const total = progress[totalKey];
    if (typeof completed === "number" && typeof total === "number" && total > 0) {
      return { completed, total, label };
    }
  }
  return { completed: 0, total: 0, label: "items" };
}

export function statusTone(status: string): { foreground: string; background: string } {
  const normalized = status.toLowerCase();
  if (["completed", "done", "approved", "auto_passed", "pass", "healthy"].includes(normalized)) {
    return { foreground: "var(--accent-positive)", background: "var(--accent-positive-glow)" };
  }
  if (["failed", "flag", "auto_flagged", "rejected", "deleted", "needs_rework"].includes(normalized)) {
    return { foreground: "var(--accent-negative)", background: "var(--accent-negative-glow)" };
  }
  if (["awaiting_review", "manual_review_required", "qa_pending", "cancel_requested", "warning"].includes(normalized)) {
    return { foreground: "var(--accent-warning)", background: "var(--accent-warning-glow)" };
  }
  return { foreground: "var(--accent-primary)", background: "var(--accent-glow)" };
}
