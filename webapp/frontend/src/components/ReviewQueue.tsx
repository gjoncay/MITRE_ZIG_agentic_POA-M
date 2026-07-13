import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { listReports } from "../api/client";
import type { ReportSummary } from "../types";
import { formatDate, reportNeedsReview, statusTone, titleCase } from "../utils/presentation";

interface ReviewQueueProps {
  onOpenReport: (reportId: string) => void;
  onOpenRun: (runId: string) => void;
}

type QueueFilter = "all" | "manual" | "flagged" | "rework";
const REVIEW_PAGE_SIZE = 100;
const REVIEW_STATE_BY_FILTER: Record<QueueFilter, string> = {
  all: "pending",
  manual: "manual",
  flagged: "flagged",
  rework: "rework",
};

/** Review work is a distinct queue, not a side effect of a completed job. */
export default function ReviewQueue({ onOpenReport, onOpenRun }: ReviewQueueProps) {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [filter, setFilter] = useState<QueueFilter>("all");
  const [search, setSearch] = useState("");
  const [pageNumber, setPageNumber] = useState(1);
  const [totalReports, setTotalReports] = useState(0);
  const [counts, setCounts] = useState<Record<QueueFilter, number>>({ all: 0, manual: 0, flagged: 0, rework: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const listRequestGeneration = useRef(0);

  const load = useCallback(async (targetPage = pageNumber) => {
    const requestGeneration = ++listRequestGeneration.current;
    setLoading(true);
    try {
      const searchValue = search.trim() || undefined;
      const [page, ...countPages] = await Promise.all([
        listReports({
          // State aliases are resolved by the backend, so every reviewable
          // row is reachable through paging rather than hidden after a local
          // first-page-only filter.
          reviewState: REVIEW_STATE_BY_FILTER[filter],
          search: searchValue,
          page: targetPage,
          pageSize: REVIEW_PAGE_SIZE,
        }),
        ...(["all", "manual", "flagged", "rework"] as QueueFilter[]).map((name) => listReports({
          reviewState: REVIEW_STATE_BY_FILTER[name],
          search: searchValue,
          page: 1,
          pageSize: 1,
        })),
      ]);
      if (requestGeneration !== listRequestGeneration.current) return;
      setReports(page.items);
      setTotalReports(page.total ?? page.items.length);
      setCounts(Object.fromEntries((['all', 'manual', 'flagged', 'rework'] as QueueFilter[]).map((name, index) => [name, countPages[index]?.total ?? 0])) as Record<QueueFilter, number>);
      setError(null);
    } catch (caught) {
      if (requestGeneration !== listRequestGeneration.current) return;
      setError(caught instanceof Error ? caught.message : "Unable to load the review queue.");
    } finally {
      if (requestGeneration === listRequestGeneration.current) setLoading(false);
    }
  }, [filter, pageNumber, search]);

  useLayoutEffect(() => {
    listRequestGeneration.current += 1;
    setPageNumber(1);
  }, [filter, search]);
  useEffect(() => { void load(); }, [load, refresh]);

  const queue = useMemo(() => reports.filter((report) => {
    if (!reportNeedsReview(report)) return false;
    return true;
  }), [reports]);

  return (
    <section className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="data-label">Required human decisions</div>
          <h2 className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>Review queue</h2>
          <p className="mt-1 max-w-3xl text-sm" style={{ color: "var(--text-secondary)" }}>
            A run stays awaiting review while any report needs a decision or rework. A rejection is retained in the audit history but is not a pass; it remains actionable until rework or an accepted replacement resolves it. Review provenance before accepting an LLM-assisted mapping.
          </p>
        </div>
        <button type="button" onClick={() => setRefresh((value) => value + 1)} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Refresh queue</button>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-4">
        {(["all", "manual", "flagged", "rework"] as QueueFilter[]).map((name) => (
          <button key={name} type="button" onClick={() => { setFilter(name); setPageNumber(1); }} className="rounded-lg border px-4 py-3 text-left" style={{ borderColor: filter === name ? "var(--accent-primary)" : "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
            <div className="data-label">{name === "all" ? "All pending" : titleCase(name)}</div>
            <div className="mt-1 text-xl font-semibold" style={{ color: filter === name ? "var(--accent-primary)" : "var(--text-primary)" }}>{counts[name]}</div>
          </button>
        ))}
      </div>

      <div className="mt-5 flex flex-wrap gap-3 rounded-lg border p-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
        <label className="sr-only" htmlFor="review-search">Search review queue</label>
        <input id="review-search" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { setPageNumber(1); void load(1); } }} placeholder="Search technique, report, or run" className="min-w-56 flex-1 rounded-md border px-3 py-2 text-sm outline-none" style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }} />
        <button type="button" onClick={() => { setPageNumber(1); void load(1); }} className="rounded-md px-3 py-2 text-sm font-semibold text-white" style={{ backgroundColor: "var(--accent-primary)" }}>Search</button>
      </div>

      {error ? <div className="mt-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}>{error}</div> : null}
      {loading ? <p className="mt-6 text-sm" style={{ color: "var(--text-secondary)" }}>Loading review queue…</p> : null}
      {!loading && !error && queue.length === 0 ? <div className="mt-5 rounded-lg border border-dashed px-6 py-12 text-center" style={{ borderColor: "var(--border-strong)", color: "var(--text-secondary)" }}>No reports currently require a review decision.</div> : null}
      {!loading && queue.length > 0 ? <><p className="mt-4 text-sm" style={{ color: "var(--text-secondary)" }}>Showing {queue.length} of {totalReports} {filter === "all" ? "pending" : titleCase(filter).toLowerCase()} report{totalReports === 1 ? "" : "s"}.</p><div className="mt-3 grid gap-3">{queue.map((report) => <ReviewCard key={report.id} report={report} onOpenReport={onOpenReport} onOpenRun={onOpenRun} />)}</div>{totalReports > REVIEW_PAGE_SIZE ? <QueuePagination page={pageNumber} total={totalReports} pageSize={REVIEW_PAGE_SIZE} onPageChange={setPageNumber} /> : null}</> : null}
    </section>
  );
}

function QueuePagination({ page, total, pageSize, onPageChange }: { page: number; total: number; pageSize: number; onPageChange: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return <div className="mt-4 flex items-center justify-between gap-3 border-t pt-4 text-sm" style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}><span>Page {page} of {pages}</span><div className="flex gap-2"><button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} className="rounded-md border px-3 py-2 text-sm disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Previous</button><button type="button" disabled={page >= pages} onClick={() => onPageChange(page + 1)} className="rounded-md border px-3 py-2 text-sm disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Next</button></div></div>;
}

function ReviewCard({ report, onOpenReport, onOpenRun }: { report: ReportSummary; onOpenReport: (reportId: string) => void; onOpenRun: (runId: string) => void }) {
  const reviewLabel = report.review_state || report.lifecycle_state || report.qa_verdict;
  const tone = statusTone(reviewLabel);
  return (
    <article className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="mono text-xs" style={{ color: "var(--text-muted)" }}>{report.display_id || report.report_id}</span><span className="rounded-full px-2 py-0.5 text-xs font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(reviewLabel)}</span></div><h3 className="mt-2 text-base font-semibold" style={{ color: "var(--text-primary)" }}>{report.technique_id} · {report.technique_name}</h3><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>{report.finding_count} finding{report.finding_count === 1 ? "" : "s"} · generated {formatDate(report.updated_at || report.generated_date)}</p></div>
        <div className="flex flex-wrap gap-2"><button type="button" onClick={() => onOpenReport(report.id)} className="rounded-md px-3 py-2 text-sm font-semibold text-white" style={{ backgroundColor: "var(--accent-primary)" }}>Review report</button>{report.run_id ? <button type="button" onClick={() => onOpenRun(report.run_id!)} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Run progress</button> : null}</div>
      </div>
    </article>
  );
}
