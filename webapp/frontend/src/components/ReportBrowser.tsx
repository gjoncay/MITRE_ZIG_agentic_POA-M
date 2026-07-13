import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { getBrowserSession, getReport, listReports, normalizeReportSummary, restoreReport, type BrowserSession } from "../api/client";
import type { DeleteReportResult, ReportSummary } from "../types";
import { formatDate, reportNeedsReview, statusTone, titleCase } from "../utils/presentation";
import ReportDetailView from "./ReportDetail";

interface ReportBrowserProps {
  selectedReportId?: string;
  runId?: string;
  session: BrowserSession | null;
  onSessionChange: (session: BrowserSession) => void;
  onSelectReport: (reportId: string) => void;
  onOpenRun: (runId: string) => void;
  onOpenReview: () => void;
}

interface UndoNotice {
  report: ReportSummary;
  expiresAt?: string | null;
  actor: string;
  version?: string | number;
}

type BrowserFilter = "all" | "needs_review" | "passed" | "flagged" | "deleted";
const REPORT_PAGE_SIZE = 100;

/** Filterable reports workspace. Server filters are requested first, then a small
 * client-side guard keeps older API deployments usable while their query contract rolls out. */
export default function ReportBrowser({ selectedReportId, runId, session, onSessionChange, onSelectReport, onOpenRun, onOpenReview }: ReportBrowserProps) {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(selectedReportId ?? null);
  const [deepLinkedReport, setDeepLinkedReport] = useState<ReportSummary | null>(null);
  const [search, setSearch] = useState("");
  const [reviewFilter, setReviewFilter] = useState<BrowserFilter>("all");
  const [pageNumber, setPageNumber] = useState(1);
  const [totalReports, setTotalReports] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [undo, setUndo] = useState<UndoNotice | null>(null);
  const [undoing, setUndoing] = useState(false);
  const [undoError, setUndoError] = useState<string | null>(null);
  const listRequestGeneration = useRef(0);

  const load = useCallback(async (targetPage = pageNumber) => {
    const requestGeneration = ++listRequestGeneration.current;
    setLoading(true);
    try {
      const reviewState = reviewFilter === "needs_review"
        ? "pending"
        : reviewFilter === "passed"
          ? "accepted"
          : reviewFilter === "flagged"
            ? "attention"
            : undefined;
      const page = await listReports({
        runId,
        search: search.trim() || undefined,
        lifecycleState: reviewFilter === "deleted" ? "deleted" : undefined,
        reviewState,
        includeDeleted: reviewFilter === "deleted",
        page: targetPage,
        pageSize: REPORT_PAGE_SIZE,
      });
      if (requestGeneration !== listRequestGeneration.current) return;
      setReports(page.items);
      setTotalReports(page.total ?? page.items.length);
      setError(null);
    } catch (caught) {
      if (requestGeneration !== listRequestGeneration.current) return;
      setError(caught instanceof Error ? caught.message : "Unable to load reports.");
    } finally {
      if (requestGeneration === listRequestGeneration.current) setLoading(false);
    }
  }, [pageNumber, reviewFilter, runId, search]);

  useLayoutEffect(() => {
    // Invalidate a request for the old page before the page-reset render can
    // issue its replacement. Without this, a slow old response can overwrite
    // the visible page-one results after a filter/search change.
    listRequestGeneration.current += 1;
    setPageNumber(1);
  }, [reviewFilter, runId, search]);
  useEffect(() => { void load(); }, [load, refreshTick]);
  useEffect(() => { if (selectedReportId) setSelectedId(selectedReportId); }, [selectedReportId]);
  useEffect(() => {
    if (!selectedReportId || reports.some((report) => report.id === selectedReportId || report.report_id === selectedReportId)) {
      setDeepLinkedReport(null);
      return;
    }
    let canceled = false;
    void getReport(selectedReportId)
      .then((detail) => { if (!canceled) setDeepLinkedReport(normalizeReportSummary(detail)); })
      .catch(() => { if (!canceled) setDeepLinkedReport(null); });
    return () => { canceled = true; };
  }, [reports, selectedReportId]);
  useEffect(() => {
    // A report opened from Review Queue can be outside the current browse
    // page. Preserve its ID while the direct detail lookup resolves instead
    // of silently replacing it with the first page item.
    if (selectedReportId) return;
    if (selectedId && reports.some((report) => report.id === selectedId)) return;
    setSelectedId(reports[0]?.id ?? null);
  }, [reports, selectedId, selectedReportId]);

  useEffect(() => {
    if (!undo?.expiresAt) return;
    const remaining = new Date(undo.expiresAt).getTime() - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) { setUndo(null); return; }
    const timer = window.setTimeout(() => setUndo(null), remaining);
    return () => window.clearTimeout(timer);
  }, [undo]);

  const visibleReports = useMemo(() => reports.filter((report) => {
    if (reviewFilter === "needs_review") return reportNeedsReview(report);
    if (reviewFilter === "passed") return report.qa_verdict === "PASS" || ["approved", "auto_passed", "waived"].includes(report.lifecycle_state);
    if (reviewFilter === "flagged") return report.qa_verdict === "FLAG" || ["auto_flagged", "needs_rework", "rejected"].includes(report.lifecycle_state);
    if (reviewFilter === "deleted") return report.lifecycle_state === "deleted";
    return true;
  }), [reports, reviewFilter]);
  const selected = visibleReports.find((report) => report.id === selectedId) ?? reports.find((report) => report.id === selectedId) ?? deepLinkedReport;
  const reviewCount = reports.filter(reportNeedsReview).length;

  const handleSelect = useCallback((reportId: string) => {
    setDeepLinkedReport(null);
    setSelectedId(reportId);
    onSelectReport(reportId);
  }, [onSelectReport]);

  const handleUpdate = useCallback((updated: ReportSummary) => {
    setReports((existing) => existing.map((report) => report.id === updated.id ? { ...report, ...updated } : report));
    setDeepLinkedReport((existing) => existing?.id === updated.id ? { ...existing, ...updated } : existing);
  }, []);

  const handleRestored = useCallback((restored: ReportSummary) => {
    // A restore initiated from Trash must remove the item from the deleted
    // result set immediately; simply merging it leaves a stale selected row
    // visible until a manual refresh.
    if (reviewFilter === "deleted") {
      setReports((existing) => existing.filter((report) => report.id !== restored.id));
      setTotalReports((total) => Math.max(0, total - 1));
      if (selectedId === restored.id) {
        setSelectedId(null);
        setDeepLinkedReport(null);
      }
    } else {
      setReports((existing) => existing.map((report) => report.id === restored.id ? { ...report, ...restored } : report));
    }
    setRefreshTick((value) => value + 1);
  }, [reviewFilter, selectedId]);

  const handleDeleted = useCallback((deleted: ReportSummary, result: DeleteReportResult, actor: string) => {
    setReports((existing) => existing.filter((report) => report.id !== deleted.id));
    setTotalReports((total) => Math.max(0, total - 1));
    setUndo({ report: deleted, expiresAt: result.undo_expires_at, actor, version: result.version });
    setUndoError(null);
    if (selectedId === deleted.id) {
      const next = reports.find((report) => report.id !== deleted.id);
      if (next) handleSelect(next.id);
      else setSelectedId(null);
    }
  }, [handleSelect, reports, selectedId]);

  async function handleUndo() {
    if (!undo) return;
    setUndoing(true);
    setUndoError(null);
    try {
      // Authenticated identities can change while an undo notice is open.
      // Resolve a fresh server principal instead of reusing a browser-local
      // display name. Development mode retains the explicit local audit actor.
      let actor = undo.actor.trim();
      if (session?.authenticationMode !== "disabled") {
        const liveSession = await getBrowserSession();
        onSessionChange(liveSession);
        if (liveSession.authenticationMode !== "disabled") actor = liveSession.actor.trim();
      }
      if (!actor) throw new Error("Use Access to establish a browser session before restoring this report.");
      const restored = await restoreReport(undo.report.id, {
        actor,
        reason: "Undo soft deletion from the report workspace.",
        version: undo.version,
      });
      setReports((existing) => [
        { ...undo.report, ...restored },
        ...existing,
      ]);
      setTotalReports((total) => total + 1);
      setUndo(null);
      handleSelect(restored.id);
    } catch (caught) {
      setUndoError(caught instanceof Error ? caught.message : "The report could not be restored. The undo window may have expired.");
    } finally {
      setUndoing(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-1">
      <aside className="custom-scrollbar flex w-[21rem] min-w-[17rem] max-w-[82vw] flex-shrink-0 flex-col overflow-y-auto border-r" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-sunken)" }}>
        <div className="border-b p-4" style={{ borderColor: "var(--border-default)" }}>
          <div className="flex items-center justify-between gap-2"><div><div className="data-label">{runId ? "Run-scoped output" : "All retained output"}</div><h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Reports</h2></div><button type="button" onClick={() => setRefreshTick((value) => value + 1)} className="rounded border px-2 py-1 text-xs" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Refresh</button></div>
          <label className="sr-only" htmlFor="report-search">Search reports</label><input id="report-search" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { setPageNumber(1); void load(1); } }} placeholder="Search reports" className="mt-3 w-full rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} />
          <label className="sr-only" htmlFor="report-review-filter">Report status filter</label><select id="report-review-filter" value={reviewFilter} onChange={(event) => setReviewFilter(event.target.value as BrowserFilter)} className="mt-2 w-full rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }}><option value="all">All reports</option><option value="needs_review">Needs review</option><option value="passed">Passed / approved</option><option value="flagged">Flagged / rework</option><option value="deleted">Trash / restore</option></select>
          <button type="button" onClick={onOpenReview} className="mt-3 text-left text-xs font-medium underline" style={{ color: reviewCount > 0 ? "var(--accent-warning)" : "var(--text-secondary)" }}>{reviewCount > 0 ? `${reviewCount} report${reviewCount === 1 ? "" : "s"} on this page require a decision` : "Open the complete review queue"} → Review queue</button>
        </div>

        {error ? <div className="m-3 rounded border p-3 text-sm" style={{ borderColor: "var(--accent-negative)", color: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)" }}>{error}</div> : null}
        {loading ? <p className="px-4 py-4 text-sm" style={{ color: "var(--text-secondary)" }}>Loading reports…</p> : null}
        {!loading && !error && visibleReports.length === 0 ? <p className="px-4 py-5 text-sm" style={{ color: "var(--text-secondary)" }}>No reports match these filters.</p> : null}
        {!loading && visibleReports.map((report) => <ReportRow key={report.id} report={report} selected={report.id === selectedId} onSelect={() => handleSelect(report.id)} />)}
        {!loading && totalReports > REPORT_PAGE_SIZE ? <Pagination page={pageNumber} total={totalReports} pageSize={REPORT_PAGE_SIZE} onPageChange={setPageNumber} /> : null}
      </aside>

      <main className="min-w-0 flex-1 overflow-hidden" style={{ backgroundColor: "var(--bg-base)" }}>
        {selected ? <ReportDetailView report={selected} session={session} onSessionChange={onSessionChange} onDeleted={handleDeleted} onUpdated={handleUpdate} onRestored={handleRestored} onOpenRun={onOpenRun} /> : <div className="flex h-full items-center justify-center px-6 text-center"><div><h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Select a report</h2><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>Use the filters to find a report, review its graph evidence, and record a decision.</p></div></div>}
      </main>

      {undo ? <div className="fixed bottom-5 right-5 z-40 max-w-md rounded-lg border p-4 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-overlay)" }}><div className="flex flex-wrap items-center gap-3"><div className="flex-1"><p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Report deleted</p><p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>{undo.report.display_id || undo.report.report_id}{undo.expiresAt ? ` · undo until ${formatDate(undo.expiresAt)}` : ""}</p></div><button type="button" onClick={() => void handleUndo()} disabled={undoing} className="rounded-md px-3 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-primary)" }}>{undoing ? "Restoring…" : "Undo"}</button></div>{undoError ? <p className="mt-2 text-xs" style={{ color: "var(--accent-negative)" }}>{undoError}</p> : null}</div> : null}
    </div>
  );
}

function Pagination({ page, total, pageSize, onPageChange }: { page: number; total: number; pageSize: number; onPageChange: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return <div className="mt-auto flex items-center justify-between gap-2 border-t px-3 py-3 text-xs" style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}><span>Page {page} of {pages} · {total} reports</span><div className="flex gap-2"><button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} className="rounded border px-2 py-1 disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Previous</button><button type="button" disabled={page >= pages} onClick={() => onPageChange(page + 1)} className="rounded border px-2 py-1 disabled:opacity-40" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Next</button></div></div>;
}

function ReportRow({ report, selected, onSelect }: { report: ReportSummary; selected: boolean; onSelect: () => void }) {
  const state = report.review_state || report.lifecycle_state || report.qa_verdict;
  const tone = statusTone(state);
  return <button type="button" onClick={onSelect} className="flex w-full flex-col gap-1 border-b px-4 py-3 text-left" style={{ borderColor: "var(--border-subtle)", backgroundColor: selected ? "var(--bg-raised)" : "transparent" }}><div className="flex items-center justify-between gap-2"><span className="mono truncate text-xs" style={{ color: "var(--text-muted)" }}>{report.technique_id}</span><span className="rounded-full px-2 py-0.5 text-[10px] font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(state)}</span></div><span className="line-clamp-2 text-sm font-medium" style={{ color: "var(--text-primary)" }}>{report.technique_name}</span><span className="text-xs" style={{ color: "var(--text-secondary)" }}>{report.finding_count} finding{report.finding_count === 1 ? "" : "s"} · {formatDate(report.updated_at || report.generated_date)}</span></button>;
}
