import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { approveRunReviewPendingReports, cancelRun, getRun, getRunEventsUrl, normalizeJobEvent, retryRun } from "../api/client";
import type { JobEvent, RunSnapshot } from "../types";
import { formatDate, formatDuration, getProgressPair, isTerminalRun, runNeedsReview, statusTone, titleCase } from "../utils/presentation";

interface ProgressViewProps {
  runId: string;
  onOpenRun: (runId: string) => void;
  onOpenReports: (runId: string, reportId?: string) => void;
  onReview: () => void;
  onBack: () => void;
}

const SNAPSHOT_INTERVAL_MS = 4000;
const EVENT_LIMIT = 80;
const DEFAULT_BULK_REVIEW_REASON = "Bulk approval after review by the local operator.";

/**
 * Durable run monitor. SSE supplies narrative events and near-real-time progress;
 * snapshots remain the source of truth and are polled as a reconnect/deployment fallback.
 */
export default function ProgressView({ runId, onOpenRun, onOpenReports, onReview, onBack }: ProgressViewProps) {
  const [run, setRun] = useState<RunSnapshot | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<"connecting" | "live" | "fallback">("connecting");
  const [canceling, setCanceling] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [bulkReviewOpen, setBulkReviewOpen] = useState(false);
  const [bulkReviewReason, setBulkReviewReason] = useState(DEFAULT_BULK_REVIEW_REASON);
  const [bulkReviewing, setBulkReviewing] = useState(false);
  const [bulkReviewError, setBulkReviewError] = useState<string | null>(null);
  const [bulkReviewNotice, setBulkReviewNotice] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const lastSequence = useRef<number>(0);
  const runGeneration = useRef(0);

  const loadSnapshot = useCallback(async () => {
    const requestedGeneration = runGeneration.current;
    try {
      const snapshot = await getRun(runId);
      if (requestedGeneration !== runGeneration.current) return null;
      setRun(snapshot);
      setError(null);
      return snapshot;
    } catch (caught) {
      if (requestedGeneration !== runGeneration.current) return null;
      const message = caught instanceof Error ? caught.message : "Unable to retrieve this run.";
      setError(message);
      return null;
    }
  }, [runId]);

  const applyEvent = useCallback((event: JobEvent, eventGeneration?: number) => {
    if (eventGeneration !== undefined && eventGeneration !== runGeneration.current) return;
    if (event.sequence && event.sequence <= lastSequence.current) return;
    if (event.sequence) lastSequence.current = event.sequence;
    setEvents((existing) => [event, ...existing].slice(0, EVENT_LIMIT));
    setRun((previous) => {
      if (!previous) return previous;
      const payload = event.payload ?? {};
      const nestedProgress = typeof payload.progress === "object" && payload.progress !== null && !Array.isArray(payload.progress)
        ? payload.progress as Record<string, unknown>
        : typeof payload.counters === "object" && payload.counters !== null && !Array.isArray(payload.counters)
          ? payload.counters as Record<string, unknown>
          : payload;
      const progress = { ...previous.progress };
      for (const [key, value] of Object.entries(nestedProgress)) {
        if (typeof value === "number" && Number.isFinite(value)) progress[key] = value;
      }
      const eventMetrics = typeof payload.metrics === "object" && payload.metrics !== null && !Array.isArray(payload.metrics)
        ? payload.metrics as Record<string, unknown>
        : {};
      const metrics = { ...previous.metrics };
      for (const [key, value] of Object.entries(eventMetrics)) {
        if (typeof value === "number" && Number.isFinite(value)) metrics[key] = value;
      }
      return {
        ...previous,
        status: event.status || previous.status,
        stage: event.stage || previous.stage,
        cancel_requested: previous.cancel_requested || event.type === "cancel_requested",
        progress,
        metrics,
      };
    });
  }, []);

  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    // React reuses this component when an operator jumps directly from one
    // run URL to another. Event sequences are per-run, so retaining A's last
    // sequence would discard B's early SSE events and briefly show stale data.
    const effectGeneration = runGeneration.current + 1;
    runGeneration.current = effectGeneration;
    lastSequence.current = 0;
    setEvents([]);
    setRun(null);
    setError(null);
    setStreamState("connecting");
    setCanceling(false);
    setRetrying(false);
    setBulkReviewOpen(false);
    setBulkReviewReason(DEFAULT_BULK_REVIEW_REASON);
    setBulkReviewing(false);
    setBulkReviewError(null);
    setBulkReviewNotice(null);
    void loadSnapshot();

    const poll = () => { if (!disposed) void loadSnapshot(); };
    const pollTimer = window.setInterval(poll, SNAPSHOT_INTERVAL_MS);
    const clockTimer = window.setInterval(() => setNow(Date.now()), 1000);

    if ("EventSource" in window) {
      try {
        source = new EventSource(getRunEventsUrl(runId));
        const handleRawEvent = (rawEvent: Event) => {
          if (disposed || effectGeneration !== runGeneration.current) return;
          const messageEvent = rawEvent as MessageEvent<string>;
          try {
            const parsed: unknown = JSON.parse(messageEvent.data);
            applyEvent(normalizeJobEvent(parsed), effectGeneration);
            setStreamState("live");
          } catch {
            // Ignore malformed event frames; the durable snapshot poll is still active.
          }
        };
        source.onopen = () => { if (!disposed && effectGeneration === runGeneration.current) setStreamState("live"); };
        source.onmessage = handleRawEvent;
        ["progress", "stage", "report", "warning", "error", "completed", "review_required"].forEach((name) => source?.addEventListener(name, handleRawEvent));
        source.onerror = () => { if (!disposed && effectGeneration === runGeneration.current) setStreamState("fallback"); };
      } catch {
        setStreamState("fallback");
      }
    } else {
      setStreamState("fallback");
    }

    return () => {
      disposed = true;
      window.clearInterval(pollTimer);
      window.clearInterval(clockTimer);
      source?.close();
    };
  }, [applyEvent, loadSnapshot, runId]);

  const pair = getProgressPair(run?.progress ?? {});
  const percent = pair.total > 0 ? Math.min(100, Math.round((pair.completed / pair.total) * 100)) : null;
  const startedAt = run?.started_at || run?.created_at;
  // Analysis generation stops before human review. Keep that distinct from
  // the later acceptance timestamp so elapsed/ETA never grows for days while
  // a reviewer is deliberating.
  const generationStoppedAt = run?.generation_finished_at || (run?.status === "completed" ? run.finished_at : undefined);
  const elapsedEnd = generationStoppedAt ? new Date(generationStoppedAt).getTime() : now;
  const elapsed = startedAt ? Math.max(0, elapsedEnd - new Date(startedAt).getTime()) : 0;
  const estimatedEta = pair.completed > 0 && pair.total > pair.completed ? elapsed * ((pair.total - pair.completed) / pair.completed) : null;
  const providerEta = run?.metrics?.eta_seconds;
  const eta = typeof providerEta === "number" ? providerEta : estimatedEta;
  const throughput = run?.metrics?.items_per_minute;
  const requiresReview = run ? runNeedsReview(run) : false;
  const failed = run?.status === "failed";
  const canceled = run?.status === "canceled";
  const workStopped = run ? isTerminalRun(run.status) || run.status === "awaiting_review" : false;
  const cancellationPending = Boolean(run && run.cancel_requested && !workStopped);
  const canCancel = run && ["queued", "pending", "running", "analysis_finished"].includes(run.status) && !run.cancel_requested && !canceling;
  const canRetry = run && ["failed", "canceled"].includes(run.status) && !retrying;
  const pendingReviewCount = run?.progress.reports_review_pending ?? 0;
  const canBulkReview = Boolean(run && requiresReview && pendingReviewCount > 0 && !bulkReviewing);

  const metricRows = useMemo(() => [
    ["Artifacts", run?.progress.artifacts_completed, run?.progress.artifacts_total],
    ["Observations", run?.progress.observations_completed, run?.progress.observations_total],
    ["Techniques", run?.progress.techniques_completed, run?.progress.techniques_total],
    ["Reports", run?.progress.reports_completed, run?.progress.reports_total],
  ] as const, [run]);

  async function handleCancel() {
    if (!run || !canCancel) return;
    setCanceling(true);
    try {
      const updated = await cancelRun(run.id, run.version);
      setRun(updated);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to cancel this run.");
    } finally {
      setCanceling(false);
    }
  }

  async function handleRetry() {
    if (!run || !canRetry) return;
    setRetrying(true);
    try {
      const retry = await retryRun(run.id);
      onOpenRun(retry.id);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create a retry run.");
      setRetrying(false);
    }
  }

  async function handleBulkReview() {
    if (!run || !canBulkReview) return;
    const reason = bulkReviewReason.trim();
    if (!reason) {
      setBulkReviewError("Enter a shared reason for this auditable bulk decision.");
      return;
    }
    if (run.version === undefined) {
      setBulkReviewError("Refresh the run before applying a bulk review decision.");
      return;
    }
    setBulkReviewing(true);
    setBulkReviewError(null);
    try {
      const result = await approveRunReviewPendingReports(run.id, { reason, version: run.version });
      setRun(result.run);
      setBulkReviewOpen(false);
      setBulkReviewNotice(`${result.approvedCount} pending report${result.approvedCount === 1 ? " was" : "s were"} marked reviewed and approved.`);
      void loadSnapshot();
    } catch (caught) {
      setBulkReviewError(caught instanceof Error ? caught.message : "Unable to record the bulk review decision.");
    } finally {
      setBulkReviewing(false);
    }
  }

  const tone = statusTone(run?.status ?? "queued");
  return (
    <section className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <button type="button" onClick={onBack} className="text-sm underline" style={{ color: "var(--text-secondary)" }}>← All runs</button>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <h2 className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>Analyst progress</h2>
            {run ? <span className="rounded-full px-2.5 py-1 text-xs font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(run.status)}</span> : null}
          </div>
          <p className="mono mt-1 text-xs" style={{ color: "var(--text-muted)" }}>{runId}</p>
          {run?.stage ? <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>{run.stage}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          {canCancel ? <button type="button" onClick={() => void handleCancel()} disabled={canceling} className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--accent-negative)", color: "var(--accent-negative)" }}>{canceling ? "Canceling…" : "Cancel run"}</button> : null}
          {cancellationPending ? <button type="button" disabled className="rounded-md border px-3 py-2 text-sm font-medium opacity-60" style={{ borderColor: "var(--accent-warning)", color: "var(--accent-warning)" }}>Cancellation requested</button> : null}
          {canRetry ? <button type="button" onClick={() => void handleRetry()} disabled={retrying} className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--accent-warning)", color: "var(--accent-warning)" }}>{retrying ? "Creating retry…" : "Retry run"}</button> : null}
          <button type="button" onClick={() => void loadSnapshot()} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Refresh</button>
        </div>
      </div>

      {error ? <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}><span>{error}</span><button type="button" onClick={() => void loadSnapshot()} className="rounded border px-2 py-1 text-xs" style={{ borderColor: "currentColor" }}>Retry snapshot</button></div> : null}

      <div className="mt-6 rounded-lg border p-5" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div><div className="data-label">Current phase</div><p className="mt-1 text-lg font-semibold" style={{ color: "var(--text-primary)" }}>{run?.stage || "Loading durable run snapshot…"}</p></div>
          <div className="text-right"><div className="data-label">Event channel</div><p className="mt-1 text-sm" style={{ color: streamState === "live" ? "var(--accent-positive)" : "var(--accent-warning)" }}>{streamState === "live" ? "Live SSE" : streamState === "connecting" ? "Connecting…" : "Snapshot polling fallback"}</p></div>
        </div>
        <div className="mt-5 h-3 overflow-hidden rounded-full" style={{ backgroundColor: "var(--bg-sunken)" }}>
          <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${percent ?? 5}%`, backgroundColor: "var(--accent-primary)" }} />
        </div>
        <div className="mt-2 flex flex-wrap justify-between gap-x-6 gap-y-1 text-xs" style={{ color: "var(--text-secondary)" }}>
          <span>{percent === null ? "Waiting for a total work count" : `${pair.completed} of ${pair.total} ${pair.label} (${percent}%)`}</span>
          <span>{startedAt ? `${generationStoppedAt ? "Generation duration" : "Elapsed"} ${formatDuration(elapsed)}` : "Start time pending"}{typeof throughput === "number" ? ` · ${throughput.toFixed(1)} items/min` : ""}{!generationStoppedAt && eta !== null ? ` · Estimated remaining ${formatDuration(eta)}` : ""}</span>
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {metricRows.map(([label, completed, total]) => <ProgressMetric key={label} label={label} completed={completed} total={total} />)}
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-4">
        <CounterCard label="Auto-passed" value={run?.progress.reports_auto_passed ?? 0} color="var(--accent-positive)" />
        <CounterCard label="Flagged" value={run?.progress.reports_flagged ?? 0} color="var(--accent-negative)" />
        <CounterCard label="Review pending" value={run?.progress.reports_review_pending ?? 0} color="var(--accent-warning)" />
        <CounterCard label="Errors / retries" value={(run?.progress.errors ?? 0) + (run?.progress.retries ?? 0)} color="var(--text-secondary)" />
      </div>

      {run?.degraded_reason ? <div className="mt-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-warning)", backgroundColor: "var(--accent-warning-glow)", color: "var(--accent-warning)" }}><strong>Degraded analysis:</strong> {run.degraded_reason}. A reviewer should validate affected mappings before approval.</div> : null}
      {run?.effective_provider ? <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>Provider: {run.effective_provider}{run.model ? ` · model ${run.model}` : ""}</p> : null}
      {bulkReviewNotice ? <div className="mt-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-positive)", backgroundColor: "var(--accent-positive-glow)", color: "var(--accent-positive)" }}>{bulkReviewNotice}</div> : null}
      {failed ? <div className="mt-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}><strong>Run failed:</strong> {run.error || "The service did not provide a reason."}</div> : null}
      {canceled ? <div className="mt-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-warning)", backgroundColor: "var(--accent-warning-glow)", color: "var(--accent-warning)" }}>This run was canceled. Already-published reports remain available for review.</div> : null}

      {run && workStopped && !failed && !canceled ? (
        <div className="mt-4 flex flex-wrap items-center justify-between gap-4 rounded-lg border p-4" style={{ borderColor: requiresReview ? "var(--accent-warning)" : "var(--accent-positive)", backgroundColor: requiresReview ? "var(--accent-warning-glow)" : "var(--accent-positive-glow)" }}>
          <div><h3 className="font-semibold" style={{ color: requiresReview ? "var(--accent-warning)" : "var(--accent-positive)" }}>{requiresReview ? "Analysis finished; review is still required" : "All required reports have passed"}</h3><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>{requiresReview ? "The run remains open until every flagged or manual-review report receives a decision." : "The run has reached its acceptance gate."}</p></div>
          <div className="flex flex-wrap gap-2">{canBulkReview ? <button type="button" onClick={() => { setBulkReviewError(null); setBulkReviewOpen(true); }} className="rounded-md px-3 py-2 text-sm font-semibold text-white" style={{ backgroundColor: "var(--accent-positive)" }}>Mark all {pendingReviewCount} pending report{pendingReviewCount === 1 ? "" : "s"} reviewed</button> : null}{requiresReview ? <button type="button" onClick={onReview} className="rounded-md px-3 py-2 text-sm font-semibold text-white" style={{ backgroundColor: "var(--accent-warning)" }}>Open review queue</button> : null}<button type="button" onClick={() => onOpenReports(run.id, run.report_ids[0])} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>View reports</button></div>
        </div>
      ) : null}

      <div className="mt-6 overflow-hidden rounded-lg border" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
        <div className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: "var(--border-default)" }}><div><div className="data-label">Analyst event log</div><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>Recent activity</h3></div><span className="text-xs" style={{ color: "var(--text-muted)" }}>{events.length} live event{events.length === 1 ? "" : "s"}</span></div>
        {events.length === 0 ? <p className="px-4 py-6 text-sm" style={{ color: "var(--text-secondary)" }}>Waiting for persisted progress events. Snapshot polling will continue if the event stream is unavailable.</p> : <ol className="custom-scrollbar max-h-80 overflow-y-auto">{events.map((event, index) => <li key={`${event.sequence ?? "event"}-${event.id ?? index}`} className="border-b px-4 py-3 last:border-b-0" style={{ borderColor: "var(--border-subtle)" }}><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{event.stage || titleCase(event.type)}</span><span className="text-xs" style={{ color: "var(--text-muted)" }}>{formatDate(event.timestamp)}</span></div>{event.message ? <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>{event.message}</p> : null}</li>)}</ol>}
      </div>
      {bulkReviewOpen && run ? <BulkReviewDialog
        pendingCount={pendingReviewCount}
        reason={bulkReviewReason}
        saving={bulkReviewing}
        error={bulkReviewError}
        onReasonChange={setBulkReviewReason}
        onCancel={() => { if (!bulkReviewing) setBulkReviewOpen(false); }}
        onConfirm={() => void handleBulkReview()}
      /> : null}
    </section>
  );
}

function ProgressMetric({ label, completed, total }: { label: string; completed?: number; total?: number }) {
  const display = typeof total === "number" ? `${completed ?? 0} / ${total}` : typeof completed === "number" ? String(completed) : "—";
  return <div className="rounded-lg border px-4 py-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="data-label">{label}</div><div className="mt-1 text-xl font-semibold" style={{ color: "var(--text-primary)" }}>{display}</div></div>;
}

function CounterCard({ label, value, color }: { label: string; value: number; color: string }) {
  return <div className="rounded-lg border px-4 py-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="data-label">{label}</div><div className="mt-1 text-xl font-semibold" style={{ color }}>{value}</div></div>;
}

function BulkReviewDialog({ pendingCount, reason, saving, error, onReasonChange, onCancel, onConfirm }: { pendingCount: number; reason: string; saving: boolean; error: string | null; onReasonChange: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="bulk-review-title" style={{ backgroundColor: "var(--bg-scrim)" }}><div className="w-full max-w-xl rounded-lg border p-5 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-overlay)" }}><h2 id="bulk-review-title" className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Mark all pending reports reviewed?</h2><p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>This approves the {pendingCount} report{pendingCount === 1 ? "" : "s"} currently awaiting review in this run only. The service records a separate, immutable approval decision for every report, using your server-side local identity.</p><label className="data-label mt-4 block" htmlFor="bulk-review-reason">Shared audit reason</label><textarea id="bulk-review-reason" value={reason} onChange={(event) => onReasonChange(event.target.value)} rows={3} disabled={saving} className="mt-2 w-full resize-y rounded-md border p-3 text-sm outline-none disabled:opacity-50" style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }} />{error ? <p className="mt-3 text-sm" style={{ color: "var(--accent-negative)" }}>{error}</p> : null}<div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} disabled={saving} className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Cancel</button><button type="button" onClick={onConfirm} disabled={saving || !reason.trim()} className="rounded-md px-3 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-positive)" }}>{saving ? "Recording approvals…" : `Approve ${pendingCount} report${pendingCount === 1 ? "" : "s"}`}</button></div></div></div>;
}
