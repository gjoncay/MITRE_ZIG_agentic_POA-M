import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { listRuns } from "../api/client";
import type { RunSnapshot } from "../types";
import { formatDate, getProgressPair, runNeedsReview, statusTone, titleCase } from "../utils/presentation";

interface RunListProps {
  onNewAnalysis: () => void;
  onOpenRun: (runId: string) => void;
  onOpenReports: (runId: string) => void;
}

const STATUS_OPTIONS = ["", "queued", "running", "analysis_finished", "awaiting_review", "completed", "failed", "canceled"];
const RUN_PAGE_SIZE = 100;

/** Durable run history. It deliberately reads fresh snapshots instead of treating a
 * browser-local job object as authority. */
export default function RunList({ onNewAnalysis, onOpenRun, onOpenReports }: RunListProps) {
  const [runs, setRuns] = useState<RunSnapshot[]>([]);
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [pageNumber, setPageNumber] = useState(1);
  const [totalRuns, setTotalRuns] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);
  const listRequestGeneration = useRef(0);

  const load = useCallback(async (targetPage = pageNumber) => {
    const requestGeneration = ++listRequestGeneration.current;
    setLoading(true);
    try {
      const page = await listRuns({ status: status || undefined, search: search.trim() || undefined, page: targetPage, pageSize: RUN_PAGE_SIZE });
      if (requestGeneration !== listRequestGeneration.current) return;
      setRuns(page.items);
      setTotalRuns(page.total ?? page.items.length);
      setError(null);
    } catch (caught) {
      if (requestGeneration !== listRequestGeneration.current) return;
      setError(caught instanceof Error ? caught.message : "Unable to load run history.");
    } finally {
      if (requestGeneration === listRequestGeneration.current) setLoading(false);
    }
  }, [pageNumber, search, status]);

  useLayoutEffect(() => {
    listRequestGeneration.current += 1;
    setPageNumber(1);
  }, [search, status]);
  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const summary = useMemo(() => ({
    active: runs.filter((run) => ["queued", "pending", "running", "analysis_finished", "cancel_requested"].includes(run.status)).length,
    review: runs.filter(runNeedsReview).length,
    complete: runs.filter((run) => ["completed", "done"].includes(run.status)).length,
  }), [runs]);

  return (
    <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="data-label">Durable analysis history</div>
          <h2 className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>Runs</h2>
          <p className="mt-1 max-w-2xl text-sm" style={{ color: "var(--text-secondary)" }}>
            Track analysis, mapping, generation, and review separately. A run only completes once its required reports have passed review.
          </p>
        </div>
        <button type="button" onClick={onNewAnalysis} className="rounded-md px-4 py-2 text-sm font-semibold text-white" style={{ backgroundColor: "var(--accent-primary)" }}>
          New analysis
        </button>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <Metric label="Active on page" value={summary.active} tone="var(--accent-primary)" />
        <Metric label="Needs review on page" value={summary.review} tone="var(--accent-warning)" />
        <Metric label="Completed on page" value={summary.complete} tone="var(--accent-positive)" />
      </div>

      <div className="mt-6 flex flex-wrap gap-3 rounded-lg border p-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
        <label className="sr-only" htmlFor="run-search">Search runs</label>
        <input
          id="run-search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          onKeyDown={(event) => { if (event.key === "Enter") { setPageNumber(1); void load(1); } }}
          placeholder="Search run ID, provider, or stage"
          className="min-w-56 flex-1 rounded-md border px-3 py-2 text-sm outline-none"
          style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }}
        />
        <label className="sr-only" htmlFor="run-status">Filter by status</label>
        <select
          id="run-status"
          value={status}
          onChange={(event) => { setStatus(event.target.value); setPageNumber(1); }}
          className="rounded-md border px-3 py-2 text-sm outline-none"
          style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }}
        >
          {STATUS_OPTIONS.map((option) => <option key={option || "all"} value={option}>{option ? titleCase(option) : "All statuses"}</option>)}
        </select>
        <button type="button" onClick={() => setRefreshToken((value) => value + 1)} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>
          Refresh
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={() => void load()} />}
      {loading ? <p className="mt-6 text-sm" style={{ color: "var(--text-secondary)" }}>Loading run history…</p> : null}
      {!loading && !error && runs.length === 0 ? (
        <EmptyState onNewAnalysis={onNewAnalysis} />
      ) : null}
      {!loading && runs.length > 0 ? (
        <><p className="mt-4 text-sm" style={{ color: "var(--text-secondary)" }}>Showing {runs.length} of {totalRuns} matching run{totalRuns === 1 ? "" : "s"}.</p><div className="mt-3 overflow-hidden rounded-lg border" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
          <div className="hidden grid-cols-[minmax(11rem,1.35fr)_minmax(8rem,.8fr)_minmax(13rem,1fr)_minmax(8rem,.6fr)_auto] gap-3 border-b px-4 py-2 text-xs font-medium uppercase tracking-wide md:grid" style={{ borderColor: "var(--border-default)", color: "var(--text-muted)" }}>
            <span>Run</span><span>Status</span><span>Progress / review</span><span>Started</span><span>Actions</span>
          </div>
          {runs.map((run) => <RunRow key={run.id} run={run} onOpenRun={onOpenRun} onOpenReports={onOpenReports} />)}
        </div>{totalRuns > RUN_PAGE_SIZE ? <RunPagination page={pageNumber} total={totalRuns} pageSize={RUN_PAGE_SIZE} onPageChange={setPageNumber} /> : null}</>
      ) : null}
    </section>
  );
}

function RunPagination({ page, total, pageSize, onPageChange }: { page: number; total: number; pageSize: number; onPageChange: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return <div className="mt-4 flex items-center justify-between gap-3 text-sm" style={{ color: "var(--text-secondary)" }}><span>Page {page} of {pages}</span><div className="flex gap-2"><button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} className="rounded-md border px-3 py-2 text-sm disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Previous</button><button type="button" disabled={page >= pages} onClick={() => onPageChange(page + 1)} className="rounded-md border px-3 py-2 text-sm disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Next</button></div></div>;
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-lg border px-4 py-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
      <div className="data-label">{label}</div>
      <div className="mt-1 text-2xl font-semibold" style={{ color: tone }}>{value}</div>
    </div>
  );
}

function RunRow({ run, onOpenRun, onOpenReports }: { run: RunSnapshot; onOpenRun: (runId: string) => void; onOpenReports: (runId: string) => void }) {
  const pair = getProgressPair(run.progress);
  const percentage = pair.total ? Math.min(100, Math.round((pair.completed / pair.total) * 100)) : null;
  const tone = statusTone(run.status);
  const review = runNeedsReview(run);
  return (
    <article className="grid gap-3 border-b px-4 py-4 last:border-b-0 md:grid-cols-[minmax(11rem,1.35fr)_minmax(8rem,.8fr)_minmax(13rem,1fr)_minmax(8rem,.6fr)_auto] md:items-center" style={{ borderColor: "var(--border-subtle)" }}>
      <div className="min-w-0">
        <button type="button" onClick={() => onOpenRun(run.id)} className="mono block max-w-full truncate text-left text-sm font-medium underline-offset-2 hover:underline" style={{ color: "var(--text-primary)" }}>
          {run.id}
        </button>
        <p className="mt-0.5 truncate text-xs" style={{ color: "var(--text-secondary)" }}>
          {run.stage || "No stage reported"}{run.effective_provider ? ` · ${run.effective_provider}` : run.requested_provider ? ` · ${run.requested_provider}` : ""}
        </p>
      </div>
      <div>
        <span className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(run.status)}</span>
        {run.degraded_reason ? <p className="mt-1 text-xs" style={{ color: "var(--accent-warning)" }}>Degraded mode</p> : null}
      </div>
      <div>
        {percentage !== null ? (
          <>
            <div className="flex justify-between gap-3 text-xs" style={{ color: "var(--text-secondary)" }}><span>{pair.completed} / {pair.total} {pair.label}</span><span>{percentage}%</span></div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full" style={{ backgroundColor: "var(--bg-sunken)" }}><div className="h-full rounded-full" style={{ width: `${percentage}%`, backgroundColor: "var(--accent-primary)" }} /></div>
          </>
        ) : <span className="text-xs" style={{ color: "var(--text-muted)" }}>Counters pending</span>}
        {review ? <p className="mt-1 text-xs font-medium" style={{ color: "var(--accent-warning)" }}>Review gate remains open</p> : null}
      </div>
      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>{formatDate(run.started_at || run.created_at)}</div>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => onOpenRun(run.id)} className="rounded border px-2.5 py-1.5 text-xs font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Monitor</button>
        <button type="button" onClick={() => onOpenReports(run.id)} className="rounded border px-2.5 py-1.5 text-xs font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Reports</button>
      </div>
    </article>
  );
}

function ErrorBanner({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}><span>{message}</span><button type="button" onClick={onRetry} className="rounded border px-2 py-1 text-xs font-medium" style={{ borderColor: "currentColor" }}>Retry</button></div>;
}

function EmptyState({ onNewAnalysis }: { onNewAnalysis: () => void }) {
  return <div className="mt-6 rounded-lg border border-dashed px-6 py-12 text-center" style={{ borderColor: "var(--border-strong)", color: "var(--text-secondary)" }}><p>No durable runs match this filter.</p><button type="button" onClick={onNewAnalysis} className="mt-3 text-sm font-medium underline" style={{ color: "var(--accent-primary)" }}>Start an analysis</button></div>;
}
