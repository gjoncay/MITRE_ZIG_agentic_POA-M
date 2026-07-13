import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  deleteReport,
  fetchReportPdf,
  getReport,
  getReportMarkdown,
  getReportRevision,
  getBrowserSession,
  normalizeReportSummary,
  rerenderReport,
  retrySourceRunForReport,
  restoreReport,
  reviewReport,
} from "../api/client";
import type { BrowserSession } from "../api/client";
import type { DeleteReportResult, ReportDetail as ReportDetailType, ReportRevision, ReportSummary, ReviewDecision } from "../types";
import { formatDate, statusTone, titleCase } from "../utils/presentation";

interface ReportDetailProps {
  report: ReportSummary;
  session: BrowserSession | null;
  onSessionChange: (session: BrowserSession) => void;
  onDeleted: (report: ReportSummary, result: DeleteReportResult, actor: string) => void;
  onUpdated: (report: ReportSummary) => void;
  onRestored?: (report: ReportSummary) => void;
  onOpenRun?: (runId: string) => void;
}

type Tab = "report" | "evidence" | "mappings" | "provenance" | "revisions" | "json";

const TAB_LABELS: Record<Tab, string> = {
  report: "Executive report",
  evidence: "Evidence",
  mappings: "Mappings & paths",
  provenance: "Provenance",
  revisions: "Revisions",
  json: "Raw JSON",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function getValue(sources: Array<Record<string, unknown>>, names: string[]): unknown {
  for (const source of sources) {
    for (const name of names) {
      if (source[name] !== undefined && source[name] !== null) return source[name];
    }
  }
  return undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
}

/** Report detail intentionally keeps legacy and new revision-shaped reports useful.
 * Markdown, structured JSON, evidence, and mapping data load independently so a
 * missing presentation export cannot hide auditable mapping facts. */
export default function ReportDetailView({ report, session, onSessionChange, onDeleted, onUpdated, onRestored, onOpenRun }: ReportDetailProps) {
  const [tab, setTab] = useState<Tab>("report");
  const [detail, setDetail] = useState<ReportDetailType | null>(null);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(true);
  const [markdownLoading, setMarkdownLoading] = useState(true);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [markdownError, setMarkdownError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [reviewDecision, setReviewDecision] = useState<ReviewDecision>("approve");
  const [developmentActor, setDevelopmentActor] = useState("");
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [reviewNote, setReviewNote] = useState("");
  const [reviewSaving, setReviewSaving] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [showDelete, setShowDelete] = useState(false);
  const [deleteReason, setDeleteReason] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [showRestore, setShowRestore] = useState(false);
  const [restoreReason, setRestoreReason] = useState("");
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [retryingSourceRun, setRetryingSourceRun] = useState(false);
  const [showRerender, setShowRerender] = useState(false);
  const [rerendering, setRerendering] = useState(false);
  const [rerenderError, setRerenderError] = useState<string | null>(null);
  const [rerenderStatus, setRerenderStatus] = useState<string | null>(null);
  const [selectedRevision, setSelectedRevision] = useState<ReportRevision | null>(null);
  const [revisionLoading, setRevisionLoading] = useState(false);
  const [revisionError, setRevisionError] = useState<string | null>(null);
  const deleteEligibleStates = ["approved", "auto_passed", "waived", "legacy"];

  useEffect(() => {
    let canceled = false;
    setTab("report");
    setDetail(null);
    setMarkdown(null);
    setDetailLoading(true);
    setMarkdownLoading(true);
    setDetailError(null);
    setMarkdownError(null);
    setSelectedRevision(null);
    setRevisionError(null);
    setReviewError(null);
    setShowDelete(false);
    setShowRestore(false);
    setShowRerender(false);
    setSessionError(null);
    setDeleteReason("");
    setRestoreReason("");
    setRestoreError(null);
    setRerenderError(null);
    setRerenderStatus(null);

    void getReport(report.id)
      .then((loaded) => {
        if (canceled) return;
        setDetail(loaded);
        setSelectedRevision(loaded.current_revision ?? loaded.revisions[0] ?? null);
        onUpdated(normalizeReportSummary(loaded));
      })
      .catch((caught) => {
        if (!canceled) setDetailError(caught instanceof Error ? caught.message : "Unable to load report data.");
      })
      .finally(() => { if (!canceled) setDetailLoading(false); });

    void getReportMarkdown(report.id)
      .then((loaded) => { if (!canceled) setMarkdown(loaded); })
      .catch((caught) => { if (!canceled) setMarkdownError(caught instanceof Error ? caught.message : "Markdown export is unavailable."); })
      .finally(() => { if (!canceled) setMarkdownLoading(false); });

    return () => { canceled = true; };
  }, [onUpdated, report.id]);

  useEffect(() => {
    if (session?.actor.trim()) setSessionError(null);
  }, [session]);

  const current = detail ?? report;
  const isDeleted = current.lifecycle_state === "deleted";
  const canDelete = deleteEligibleStates.includes(current.lifecycle_state);
  const currentRecord = toRecord(detail);
  const revisionRecord = toRecord(selectedRevision?.data);
  const dataRecord = toRecord(detail?.data);
  const sources = useMemo(() => [revisionRecord, dataRecord, currentRecord], [currentRecord, dataRecord, revisionRecord]);
  const effectiveMarkdown = markdown ?? selectedRevision?.markdown ?? detail?.markdown ?? null;
  const reportTone = statusTone(current.lifecycle_state || current.qa_verdict);
  const evidence = getValue(sources, ["evidence", "evidence_spans", "affected_hosts", "observations", "findings", "source_observations"]);
  const candidates = getValue(sources, ["candidates", "technique_candidates"]);
  const mappings = getValue(sources, ["framework_mappings", "mappings", "mapping_paths", "graph_paths"]);
  const provenance = getValue(sources, ["provenance", "mapping_provenance", "traceability", "graph_snapshot", "source_provenance"]);
  const revisions = detail?.revisions ?? [];
  const isDevelopment = session?.authenticationMode === "disabled";
  const authenticatedActor = !isDevelopment ? session?.actor.trim() || null : null;
  const effectiveSessionError = isDevelopment
    ? null
    : sessionError || (!authenticatedActor ? "Use Access to establish a browser session before taking a privileged action." : null);

  function requireDevelopmentActor(): string {
    const actor = developmentActor.trim();
    if (!actor) throw new Error("Reviewer identity is required in development mode.");
    return actor;
  }

  async function requireAuditActor(): Promise<string> {
    if (isDevelopment) return requireDevelopmentActor();
    try {
      const liveSession = await getBrowserSession();
      onSessionChange(liveSession);
      if (liveSession.authenticationMode === "disabled") return requireDevelopmentActor();
      const actor = liveSession.actor.trim();
      if (!actor) throw new Error("The server did not return an authenticated identity.");
      setSessionError(null);
      return actor;
    } catch (caught) {
      setSessionError("Use Access to establish a browser session before taking a privileged action.");
      throw caught;
    }
  }

  async function handleExportPdf() {
    setExporting(true);
    try {
      const blob = await fetchReportPdf(report.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${report.display_id || report.report_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (caught) {
      setDetailError(caught instanceof Error ? caught.message : "Failed to export PDF.");
    } finally {
      setExporting(false);
    }
  }

  async function handleReview() {
    if (!reviewNote.trim()) {
      setReviewError("A decision note is required for the audit trail.");
      return;
    }
    setReviewSaving(true);
    setReviewError(null);
    try {
      const actor = await requireAuditActor();
      const updated = await reviewReport(report.id, {
        decision: reviewDecision,
        actor,
        note: reviewNote.trim(),
        version: detail?.version ?? detail?.current_revision_number ?? report.version,
      });
      setDetail(updated);
      setSelectedRevision(updated.current_revision ?? updated.revisions[0] ?? null);
      setReviewNote("");
      onUpdated(normalizeReportSummary(updated));
    } catch (caught) {
      setReviewError(caught instanceof Error ? caught.message : "Unable to save review decision.");
    } finally {
      setReviewSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteReason.trim()) {
      setDeleteError("A deletion reason is required for the audit record.");
      return;
    }
    setDeleting(true);
    setDeleteError(null);
    try {
      const actor = await requireAuditActor();
      const result = await deleteReport(report.id, {
        reason: deleteReason.trim(),
        actor,
        version: detail?.version ?? detail?.current_revision_number ?? report.version,
      });
      onDeleted(report, result, actor);
      setShowDelete(false);
    } catch (caught) {
      setDeleteError(caught instanceof Error ? caught.message : "Unable to delete this report.");
    } finally {
      setDeleting(false);
    }
  }

  async function handleRestore() {
    setRestoring(true);
    setRestoreError(null);
    try {
      const actor = await requireAuditActor();
      const restored = await restoreReport(report.id, {
        actor,
        reason: restoreReason.trim() || "Restored from the report trash workspace.",
        version: detail?.version ?? detail?.current_revision_number ?? report.version,
      });
      setDetail(restored);
      setSelectedRevision(restored.current_revision ?? restored.revisions[0] ?? null);
      setShowRestore(false);
      const summary = normalizeReportSummary(restored);
      if (onRestored) onRestored(summary);
      else onUpdated(summary);
    } catch (caught) {
      setRestoreError(caught instanceof Error ? caught.message : "Unable to restore this report. The undo window may have expired.");
    } finally {
      setRestoring(false);
    }
  }

  async function handleRetrySourceRun() {
    setRetryingSourceRun(true);
    setDetailError(null);
    try {
      const run = await retrySourceRunForReport(report.id);
      if (onOpenRun) onOpenRun(run.id);
    } catch (caught) {
      setDetailError(caught instanceof Error ? caught.message : "Unable to start a retry of the source run.");
    } finally {
      setRetryingSourceRun(false);
    }
  }

  async function handleRerenderReport() {
    setRerendering(true);
    setRerenderError(null);
    setRerenderStatus(null);
    try {
      const updated = await rerenderReport(report.id);
      setDetail(updated);
      setSelectedRevision(updated.current_revision ?? updated.revisions[0] ?? null);
      onUpdated(normalizeReportSummary(updated));
      setShowRerender(false);
      setTab("report");

      // Markdown is a separately cached representation, so refresh it after
      // the renderer succeeds instead of relying on the pre-action response.
      setMarkdownLoading(true);
      try {
        const refreshedMarkdown = await getReportMarkdown(report.id);
        setMarkdown(refreshedMarkdown);
        setMarkdownError(null);
      } catch (caught) {
        setMarkdown(updated.markdown ?? null);
        setMarkdownError(caught instanceof Error ? caught.message : "The report was re-rendered, but its Markdown export could not be refreshed.");
      } finally {
        setMarkdownLoading(false);
      }
      setRerenderStatus("A new report revision was re-rendered with the current template and graph-backed presentation data, then returned to manual review. No source-run replay or LLM request was run.");
    } catch (caught) {
      setRerenderError(caught instanceof Error ? caught.message : "Unable to re-render this report.");
    } finally {
      setRerendering(false);
    }
  }

  async function selectRevision(revision: ReportRevision) {
    setSelectedRevision(revision);
    setRevisionError(null);
    if (revision.data || revision.markdown || !revision.id || revision.id.startsWith("revision-")) return;
    setRevisionLoading(true);
    try {
      const loaded = await getReportRevision(report.id, revision.id);
      setSelectedRevision(loaded);
    } catch (caught) {
      setRevisionError(caught instanceof Error ? caught.message : "Unable to load this immutable revision.");
    } finally {
      setRevisionLoading(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-start justify-between gap-4 border-b px-4 py-4 sm:px-6" style={{ borderColor: "var(--border-default)" }}>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2"><span className="mono text-xs" style={{ color: "var(--text-muted)" }}>{current.display_id || current.report_id}</span><span className="rounded-full px-2 py-0.5 text-xs font-semibold" style={{ color: reportTone.foreground, backgroundColor: reportTone.background }}>{titleCase(current.lifecycle_state || current.qa_verdict)}</span>{current.qa_verdict ? <span className="text-xs font-medium" style={{ color: current.qa_verdict === "PASS" ? "var(--accent-positive)" : current.qa_verdict === "FLAG" ? "var(--accent-negative)" : "var(--text-muted)" }}>QA {current.qa_verdict}</span> : null}</div>
          <h2 className="mt-2 text-lg font-semibold" style={{ color: "var(--text-primary)" }}>{current.technique_id} · {current.technique_name}</h2>
          <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>{current.finding_count} linked finding{current.finding_count === 1 ? "" : "s"}{current.run_id ? " · durable run provenance available" : " · legacy report"}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 print-hide">
          {isDeleted ? <button type="button" onClick={() => { setShowRestore(true); setRestoreError(null); }} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--accent-positive)", color: "var(--accent-positive)" }}>Restore report</button> : <>{current.run_id && onOpenRun ? <button type="button" onClick={() => onOpenRun(current.run_id!)} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Run progress</button> : null}{current.lifecycle_state !== "legacy" ? <button type="button" onClick={() => { setShowRerender(true); setRerenderError(null); }} disabled={rerendering} title="Creates a new report revision with current graph-backed presentation data without submitting evidence to an LLM or retrying the source run." className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--accent-primary)", color: "var(--accent-primary)" }}>{rerendering ? "Re-rendering…" : "Re-render with current template"}</button> : null}{current.lifecycle_state !== "legacy" && onOpenRun ? <button type="button" onClick={() => void handleRetrySourceRun()} disabled={retryingSourceRun} title="Creates a new analysis run for the retained source artifact and regenerates every report from it." className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--accent-warning)", color: "var(--accent-warning)" }}>{retryingSourceRun ? "Starting source-run retry…" : "Retry source run"}</button> : null}<button type="button" onClick={() => void handleExportPdf()} disabled={exporting} className="rounded-md border px-3 py-2 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>{exporting ? "Exporting…" : "Export PDF"}</button>{canDelete ? <button type="button" onClick={() => { setShowDelete(true); setDeleteError(null); }} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--accent-negative)", color: "var(--accent-negative)" }}>Delete</button> : <span className="text-xs" title="Record an accepted review decision before deleting this report so the run cannot finish with unreviewed work." style={{ color: "var(--text-tertiary)" }}>Delete unlocks after review</span>}</>}
        </div>
      </header>

      <div className="custom-scrollbar flex min-h-0 flex-1 flex-col overflow-y-auto">
        <nav className="sticky top-0 z-10 flex overflow-x-auto border-b px-4 sm:px-6 print-hide" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)" }} aria-label="Report detail tabs">
          {(Object.keys(TAB_LABELS) as Tab[]).map((name) => <button key={name} type="button" onClick={() => setTab(name)} className="whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium" style={{ borderColor: tab === name ? "var(--accent-primary)" : "transparent", color: tab === name ? "var(--text-primary)" : "var(--text-secondary)" }}>{TAB_LABELS[name]}</button>)}
        </nav>

        <div className="px-4 py-5 sm:px-6">
          {detailError ? <div className="mb-4 rounded-md border px-4 py-3 text-sm" style={{ borderColor: "var(--accent-negative)", backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}>{detailError}</div> : null}
          {rerenderStatus ? <div className="mb-4 rounded-md border px-4 py-3 text-sm" role="status" style={{ borderColor: "var(--accent-positive)", backgroundColor: "var(--accent-positive-glow)", color: "var(--accent-positive)" }}>{rerenderStatus}</div> : null}
          {detailLoading && tab !== "report" ? <p style={{ color: "var(--text-secondary)" }}>Loading auditable report data…</p> : null}
          {!detailLoading || tab === "report" ? <>
            {tab === "report" ? <ReportTab loading={markdownLoading} markdown={effectiveMarkdown} error={markdownError} fallback={sources} /> : null}
            {tab === "evidence" ? <EvidenceTab value={evidence} fallbackSources={sources} /> : null}
            {tab === "mappings" ? <MappingTab value={mappings} candidates={candidates} fallbackSources={sources} /> : null}
            {tab === "provenance" ? <ProvenanceTab value={provenance} sources={sources} /> : null}
            {tab === "revisions" ? <RevisionsTab revisions={revisions} selected={selectedRevision} loading={revisionLoading} error={revisionError} onSelect={(revision) => void selectRevision(revision)} /> : null}
            {tab === "json" ? <RawJsonTab value={detail ?? report} /> : null}
          </> : null}
        </div>

        {isDeleted ? <section className="border-t px-4 py-5 text-sm sm:px-6" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)", color: "var(--text-secondary)" }}>This report is in the soft-delete trash. It cannot be reviewed or reprocessed until restored, and restoration remains available only during the configured retention window.</section> : <ReviewPanel
          state={current.lifecycle_state}
          verdict={current.qa_verdict}
          actor={isDevelopment ? developmentActor : authenticatedActor}
          developmentMode={isDevelopment}
          sessionError={effectiveSessionError}
          note={reviewNote}
          decision={reviewDecision}
          saving={reviewSaving}
          error={reviewError}
          onActorChange={setDevelopmentActor}
          onNoteChange={setReviewNote}
          onDecisionChange={setReviewDecision}
          onSave={() => void handleReview()}
        />}
      </div>

      {showDelete ? <DeleteDialog report={current} actor={isDevelopment ? developmentActor : authenticatedActor} developmentMode={isDevelopment} sessionError={effectiveSessionError} reason={deleteReason} error={deleteError} deleting={deleting} onActorChange={setDevelopmentActor} onReasonChange={setDeleteReason} onCancel={() => setShowDelete(false)} onConfirm={() => void handleDelete()} /> : null}
      {showRestore ? <RestoreDialog report={current} actor={isDevelopment ? developmentActor : authenticatedActor} developmentMode={isDevelopment} sessionError={effectiveSessionError} reason={restoreReason} error={restoreError} restoring={restoring} onActorChange={setDevelopmentActor} onReasonChange={setRestoreReason} onCancel={() => setShowRestore(false)} onConfirm={() => void handleRestore()} /> : null}
      {showRerender ? <RerenderDialog report={current} error={rerenderError} rerendering={rerendering} onCancel={() => setShowRerender(false)} onConfirm={() => void handleRerenderReport()} /> : null}
    </div>
  );
}

function ReportTab({ loading, markdown, error, fallback }: { loading: boolean; markdown: string | null; error: string | null; fallback: Array<Record<string, unknown>> }) {
  const summary = getValue(fallback, ["threat_input_summary", "exploitation_scenario", "business_impact", "qa_notes"]);
  if (loading) return <p style={{ color: "var(--text-secondary)" }}>Loading rendered report…</p>;
  if (markdown) return <article className="markdown-body max-w-none"><ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown></article>;
  return <div className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>Rendered Markdown unavailable</h3><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>{error || "This revision did not include a Markdown export. The structured evidence and mappings remain available in the other tabs."}</p>{summary ? <p className="mt-3 text-sm" style={{ color: "var(--text-primary)" }}>{String(summary)}</p> : null}</div>;
}

function EvidenceTab({ value, fallbackSources }: { value: unknown; fallbackSources: Array<Record<string, unknown>> }) {
  const evidence = asArray(value);
  if (evidence.length === 0) {
    const text = getValue(fallbackSources, ["threat_input_summary", "finding_text", "source_text"]);
    return <EmptyData title="No normalized evidence spans were returned" detail={text ? String(text) : "This legacy report may not have durable observation records or a retained source artifact for a source-run retry."} />;
  }
  return <section><SectionHeading eyebrow="Traceable source material" title={`Evidence (${evidence.length})`} description="Each observation should retain its artifact/source locator, exact span or finding text, and mapping method." /><div className="mt-4 grid gap-3">{evidence.map((item, index) => <EvidenceCard key={index} value={item} index={index} />)}</div></section>;
}

function EvidenceCard({ value, index }: { value: unknown; index: number }) {
  const item = toRecord(value);
  const text = getValue([item], ["text", "finding_text", "finding", "raw_text", "evidence_text", "normalized_text"]);
  const locator = getValue([item], ["source_locator", "locator", "source", "sheet", "artifact_id", "id"]);
  const method = getValue([item], ["method", "mapping_method", "state", "severity"]);
  return <article className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="flex flex-wrap items-center justify-between gap-2"><span className="data-label">Observation {index + 1}</span>{method ? <span className="rounded-full px-2 py-0.5 text-xs" style={{ color: "var(--accent-primary)", backgroundColor: "var(--accent-glow)" }}>{String(method)}</span> : null}</div>{text ? <p className="mt-2 whitespace-pre-wrap text-sm" style={{ color: "var(--text-primary)" }}>{String(text)}</p> : <DataTree value={item} />}{locator ? <p className="mono mt-3 text-xs" style={{ color: "var(--text-muted)" }}>Source: {String(locator)}</p> : null}</article>;
}

function MappingTab({ value, candidates, fallbackSources }: { value: unknown; candidates: unknown; fallbackSources: Array<Record<string, unknown>> }) {
  const candidateSection = <CandidateSection value={candidates} />;
  if (value === undefined || value === null) {
    const legacy = collectLegacyMappings(fallbackSources);
    if (legacy.length === 0) return <section>{candidateSection}<EmptyData title="No validated mapping paths were returned" detail="A new report should enumerate real graph nodes, relationship types, path scope, and graph snapshot. This legacy report does not retain a source artifact for a source-run retry." /></section>;
    return <section>{candidateSection}<SectionHeading eyebrow="Legacy framework fields" title="Available mapping data" description="These fields predate path-level provenance and should not be interpreted as a complete graph traversal." /><div className="mt-4 grid gap-3">{legacy.map(([label, item]) => <DataCard key={label} label={label} value={item} />)}</div></section>;
  }
  const record = toRecord(value);
  const categories: Array<[string, unknown]> = isRecord(value)
    ? Object.entries(record).filter(([label]) => label !== "paths")
    : [["Mappings", value]];
  const paths = asArray(record.paths);
  return <section>{candidateSection}<SectionHeading eyebrow="Validated graph traversal" title="Mappings & paths" description="Only graph-backed node IDs, edge types, and explicit inherited-parent scopes should be presented as authoritative." /><div className="mt-4 grid gap-3">{categories.map(([label, item]) => <MappingCategory key={label} label={label} value={item} />)}</div>{paths.length > 0 ? <PathList paths={paths} /> : null}</section>;
}

function PathList({ paths }: { paths: unknown[] }) {
  const [visible, setVisible] = useState(50);
  const shown = paths.slice(0, visible);
  return <section className="mt-6 rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="flex flex-wrap items-center justify-between gap-3"><div><div className="data-label">Complete validated provenance</div><h3 className="mt-1 font-semibold" style={{ color: "var(--text-primary)" }}>Graph paths ({paths.length})</h3><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>Paths are paged in the browser to keep high-fan-out techniques reviewable without hiding any retained graph evidence.</p></div><span className="text-xs" style={{ color: "var(--text-muted)" }}>Showing {shown.length} of {paths.length}</span></div><div className="mt-4 grid gap-3">{shown.map((path, index) => <MappingEntry key={String(toRecord(path).path_id || index)} value={path} />)}</div>{visible < paths.length ? <button type="button" onClick={() => setVisible((count) => Math.min(paths.length, count + 50))} className="mt-4 rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Show 50 more paths</button> : null}</section>;
}

function CandidateSection({ value }: { value: unknown }) {
  const candidates = asArray(value);
  if (candidates.length === 0) return null;
  return <section className="mb-6"><SectionHeading eyebrow="Evidence-first selection" title={`ATT&CK candidates (${candidates.length})`} description="Candidate state, method, score, and source locator are retained separately from the final graph mapping." /><div className="mt-4 grid gap-3">{candidates.map((candidate, index) => {
    const item = toRecord(candidate);
    const state = String(getValue([item], ["state", "status"]) || "unknown");
    const tone = statusTone(state);
    const technique = getValue([item], ["technique_id", "attack_id"]);
    const method = getValue([item], ["method", "resolution_method"]);
    const score = getValue([item], ["score", "resolution_score"]);
    const reason = getValue([item], ["reason", "validation_reason"]);
    const locator = getValue([item], ["source_locator", "locator"]);
    return <article key={String(item.id || index)} className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="flex flex-wrap items-center justify-between gap-2"><span className="mono text-sm" style={{ color: "var(--text-primary)" }}>{String(technique || "Unresolved technique")}</span><span className="rounded-full px-2 py-0.5 text-xs font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(state)}</span></div><div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs" style={{ color: "var(--text-secondary)" }}><span>Method: {String(method || "unknown")}</span>{score !== undefined && score !== null ? <span>Score: {String(score)}</span> : null}</div>{reason ? <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>{String(reason)}</p> : null}{locator ? <p className="mono mt-2 text-xs" style={{ color: "var(--text-muted)" }}>Source: {typeof locator === "string" ? locator : JSON.stringify(locator)}</p> : null}</article>;
  })}</div></section>;
}

function MappingCategory({ label, value }: { label: string; value: unknown }) {
  const entries = asArray(value);
  return <article className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>{titleCase(label)}</h3>{entries.length === 0 ? <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>Explicitly not mapped.</p> : <div className="mt-3 grid gap-3">{entries.map((entry, index) => <MappingEntry key={index} value={entry} />)}</div>}</article>;
}

function MappingEntry({ value }: { value: unknown }) {
  const item = toRecord(value);
  const category = getValue([item], ["category", "type", "mapping_scope"]);
  const nodes = getValue([item], ["nodes", "path_nodes", "node_path"]);
  const edges = getValue([item], ["edges", "path_edges", "edge_path"]);
  if (Object.keys(item).length === 0) return <p className="text-sm" style={{ color: "var(--text-secondary)" }}>{String(value)}</p>;
  return <div className="rounded-md border p-3" style={{ borderColor: "var(--border-subtle)", backgroundColor: "var(--bg-base)" }}>{category ? <div className="mb-2 text-xs font-medium" style={{ color: "var(--accent-primary)" }}>{titleCase(String(category))}</div> : null}{nodes || edges ? <GraphPath nodes={nodes} edges={edges} /> : <DataTree value={item} depth={0} />}</div>;
}

function GraphPath({ nodes, edges }: { nodes: unknown; edges: unknown }) {
  const nodeItems = asArray(nodes);
  const edgeItems = asArray(edges);
  return <div><div className="flex flex-wrap items-center gap-1.5">{nodeItems.map((node, index) => <span key={index} className="mono rounded px-2 py-1 text-xs" style={{ backgroundColor: "var(--bg-raised)", color: "var(--text-primary)" }}>{nodeLabel(node)}</span>)}</div>{edgeItems.length > 0 ? <details className="mt-3"><summary className="cursor-pointer text-xs font-medium" style={{ color: "var(--text-secondary)" }}>{edgeItems.length} relationship{edgeItems.length === 1 ? "" : "s"} with provenance</summary><div className="mt-2"><DataTree value={edgeItems} /></div></details> : null}</div>;
}

function nodeLabel(value: unknown): string {
  if (typeof value === "string") return value;
  const node = toRecord(value);
  return String(getValue([node], ["id", "node_id", "name", "label"]) ?? JSON.stringify(value));
}

function ProvenanceTab({ value, sources }: { value: unknown; sources: Array<Record<string, unknown>> }) {
  const fallback = value ?? {
    graph_snapshot_id: getValue(sources, ["graph_snapshot_id", "graph_version"]),
    traceability: getValue(sources, ["traceability"]),
    report_id: getValue(sources, ["report_id"]),
    generated_date: getValue(sources, ["generated_date"]),
  };
  return <section><SectionHeading eyebrow="Audit record" title="Provenance" description="Use this record to verify artifact identity, evidence source, graph snapshot, mapping path, model/provider, and reviewer decisions." /><div className="mt-4 rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><DataTree value={fallback} /></div></section>;
}

function RevisionsTab({ revisions, selected, loading, error, onSelect }: { revisions: ReportRevision[]; selected: ReportRevision | null; loading: boolean; error: string | null; onSelect: (revision: ReportRevision) => void }) {
  if (revisions.length === 0) return <EmptyData title="No revision history available" detail="Legacy file reports have one mutable representation. Durable reports retain immutable revisions and mapping snapshots." />;
  return <section><SectionHeading eyebrow="Immutable output history" title="Revisions" description="Selecting a revision never changes the current report. Use this view to compare mapping snapshots and review history." /><div className="mt-4 grid gap-3 lg:grid-cols-[minmax(13rem,.7fr)_minmax(0,1.3fr)]"><div className="overflow-hidden rounded-lg border" style={{ borderColor: "var(--border-default)" }}>{revisions.map((revision) => <button key={revision.id} type="button" onClick={() => onSelect(revision)} className="w-full border-b px-4 py-3 text-left last:border-b-0" style={{ borderColor: "var(--border-subtle)", backgroundColor: selected?.id === revision.id ? "var(--bg-raised)" : "transparent" }}><div className="flex justify-between gap-2"><span className="font-medium" style={{ color: "var(--text-primary)" }}>Revision {revision.number}</span><span className="text-xs" style={{ color: "var(--text-muted)" }}>{revision.qa_verdict || revision.state || "Published"}</span></div><p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>{formatDate(revision.created_at)}</p></button>)}</div><div className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>{loading ? <p style={{ color: "var(--text-secondary)" }}>Loading revision…</p> : error ? <p style={{ color: "var(--accent-negative)" }}>{error}</p> : selected ? <><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>Revision {selected.number}</h3><p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>Created {formatDate(selected.created_at)}{selected.author ? ` by ${selected.author}` : ""}</p>{selected.mapping_snapshot_hash ? <p className="mono mt-3 text-xs" style={{ color: "var(--text-muted)" }}>Mapping snapshot: {selected.mapping_snapshot_hash}</p> : null}<div className="mt-4"><DataTree value={selected.data ?? selected} /></div></> : null}</div></div></section>;
}

function RawJsonTab({ value }: { value: unknown }) {
  return <pre className="mono overflow-x-auto rounded-md border p-4 text-xs" style={{ backgroundColor: "var(--bg-surface)", borderColor: "var(--border-default)", color: "var(--text-primary)" }}>{JSON.stringify(value, null, 2)}</pre>;
}

function ReviewPanel({ state, verdict, actor, developmentMode, sessionError, note, decision, saving, error, onActorChange, onNoteChange, onDecisionChange, onSave }: { state: string; verdict: string; actor: string | null; developmentMode: boolean; sessionError: string | null; note: string; decision: ReviewDecision; saving: boolean; error: string | null; onActorChange: (value: string) => void; onNoteChange: (value: string) => void; onDecisionChange: (value: ReviewDecision) => void; onSave: () => void }) {
  const tone = statusTone(state || verdict);
  const identityReady = Boolean(actor?.trim());
  return <section className="border-t px-4 py-5 sm:px-6 print-hide" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><div className="flex flex-wrap items-center justify-between gap-2"><div><div className="data-label">Review decision</div><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>Record an auditable reviewer action</h3></div><span className="rounded-full px-2 py-0.5 text-xs font-semibold" style={{ color: tone.foreground, backgroundColor: tone.background }}>{titleCase(state || verdict)}</span></div><div className="mt-4 grid gap-3 md:grid-cols-[minmax(10rem,.45fr)_minmax(12rem,.6fr)_minmax(0,1.5fr)_auto]"><select value={decision} onChange={(event) => onDecisionChange(event.target.value as ReviewDecision)} className="rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }}><option value="approve">Approve</option><option value="needs_rework">Request rework</option><option value="reject">Reject</option><option value="waive">Waive</option></select>{developmentMode ? <input value={actor || ""} onChange={(event) => onActorChange(event.target.value)} placeholder="Reviewer identity" aria-label="Reviewer identity" className="rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} /> : <div className="rounded-md border px-3 py-2 text-sm" aria-label="Authenticated reviewer identity" title="This identity comes from the current server session and cannot be edited here." style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-raised)", color: "var(--text-primary)" }}>{actor || "Checking authenticated session…"}</div>}<input value={note} onChange={(event) => onNoteChange(event.target.value)} placeholder="Decision rationale (required)" className="rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} /><button type="button" onClick={onSave} disabled={saving || !identityReady} className="rounded-md px-4 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-primary)" }}>{saving ? "Saving…" : "Save decision"}</button></div>{developmentMode ? <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>Development mode records the supplied reviewer identity. Deployed sessions always use the server-authenticated identity.</p> : null}{sessionError ? <p className="mt-3 text-sm" style={{ color: "var(--accent-warning)" }}>{sessionError}</p> : null}{error ? <p className="mt-3 text-sm" style={{ color: "var(--accent-negative)" }}>{error}</p> : null}</section>;
}

function DeleteDialog({ report, actor, developmentMode, sessionError, reason, error, deleting, onActorChange, onReasonChange, onCancel, onConfirm }: { report: ReportSummary; actor: string | null; developmentMode: boolean; sessionError: string | null; reason: string; error: string | null; deleting: boolean; onActorChange: (value: string) => void; onReasonChange: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  const identityReady = Boolean(actor?.trim());
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="delete-report-title" style={{ backgroundColor: "var(--bg-scrim)" }}><div className="w-full max-w-lg rounded-lg border p-5 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-overlay)" }}><h2 id="delete-report-title" className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Delete report?</h2><p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}><span className="mono">{report.display_id || report.report_id}</span> will be soft-deleted and recorded in the deletion audit trail. It can be restored during the service’s configured undo window.</p><div className="mt-4"><div className="data-label">{developmentMode ? "Operator identity" : "Authenticated operator"}</div>{developmentMode ? <input value={actor || ""} onChange={(event) => onActorChange(event.target.value)} placeholder="Reviewer or operator identity" aria-label="Operator identity" className="mt-2 w-full rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} /> : <div className="mt-2 rounded-md border px-3 py-2 text-sm" aria-label="Authenticated operator identity" title="This identity comes from the current server session and cannot be edited here." style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-raised)", color: "var(--text-primary)" }}>{actor || "Checking authenticated session…"}</div>}</div><label className="data-label mt-4 block" htmlFor="delete-reason">Reason for deletion</label><textarea id="delete-reason" value={reason} onChange={(event) => onReasonChange(event.target.value)} rows={3} className="mt-2 w-full rounded-md border p-3 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} placeholder="Duplicate, incorrect source, superseded report…" />{sessionError ? <p className="mt-2 text-sm" style={{ color: "var(--accent-warning)" }}>{sessionError}</p> : null}{error ? <p className="mt-2 text-sm" style={{ color: "var(--accent-negative)" }}>{error}</p> : null}<div className="mt-4 flex justify-end gap-2"><button type="button" onClick={onCancel} disabled={deleting} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Cancel</button><button type="button" onClick={onConfirm} disabled={deleting || !identityReady} className="rounded-md px-3 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-negative)" }}>{deleting ? "Deleting…" : "Delete report"}</button></div></div></div>;
}

function RestoreDialog({ report, actor, developmentMode, sessionError, reason, error, restoring, onActorChange, onReasonChange, onCancel, onConfirm }: { report: ReportSummary; actor: string | null; developmentMode: boolean; sessionError: string | null; reason: string; error: string | null; restoring: boolean; onActorChange: (value: string) => void; onReasonChange: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  const identityReady = Boolean(actor?.trim());
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="restore-report-title" style={{ backgroundColor: "var(--bg-scrim)" }}><div className="w-full max-w-lg rounded-lg border p-5 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-overlay)" }}><h2 id="restore-report-title" className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Restore report?</h2><p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}><span className="mono">{report.display_id || report.report_id}</span> will return to its last accepted lifecycle state and be recorded in the restoration audit trail.</p><div className="mt-4"><div className="data-label">{developmentMode ? "Operator identity" : "Authenticated operator"}</div>{developmentMode ? <input value={actor || ""} onChange={(event) => onActorChange(event.target.value)} placeholder="Reviewer or operator identity" aria-label="Operator identity" className="mt-2 w-full rounded-md border px-3 py-2 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} /> : <div className="mt-2 rounded-md border px-3 py-2 text-sm" aria-label="Authenticated operator identity" title="This identity comes from the current server session and cannot be edited here." style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-raised)", color: "var(--text-primary)" }}>{actor || "Checking authenticated session…"}</div>}</div><label className="data-label mt-4 block" htmlFor="restore-reason">Reason for restoration</label><textarea id="restore-reason" value={reason} onChange={(event) => onReasonChange(event.target.value)} rows={3} className="mt-2 w-full rounded-md border p-3 text-sm outline-none" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-base)", color: "var(--text-primary)" }} placeholder="Restore after verification…" />{sessionError ? <p className="mt-2 text-sm" style={{ color: "var(--accent-warning)" }}>{sessionError}</p> : null}{error ? <p className="mt-2 text-sm" style={{ color: "var(--accent-negative)" }}>{error}</p> : null}<div className="mt-4 flex justify-end gap-2"><button type="button" onClick={onCancel} disabled={restoring} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Cancel</button><button type="button" onClick={onConfirm} disabled={restoring || !identityReady} className="rounded-md px-3 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-positive)" }}>{restoring ? "Restoring…" : "Restore report"}</button></div></div></div>;
}

function RerenderDialog({ report, error, rerendering, onCancel, onConfirm }: { report: ReportSummary; error: string | null; rerendering: boolean; onCancel: () => void; onConfirm: () => void }) {
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="rerender-report-title" style={{ backgroundColor: "var(--bg-scrim)" }}><div className="w-full max-w-lg rounded-lg border p-5 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-overlay)" }}><h2 id="rerender-report-title" className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Re-render with current template?</h2><p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}><span className="mono">{report.display_id || report.report_id}</span> will receive a new immutable revision rebuilt from its retained structured report data and current validated graph mappings.</p><div className="mt-4 rounded-md border px-3 py-3 text-sm" style={{ borderColor: "var(--accent-primary)", backgroundColor: "var(--accent-glow)", color: "var(--text-primary)" }}><strong>This is a graph-backed presentation refresh.</strong> It does not submit evidence to an LLM or retry the source run. The resulting revision will return to manual review so its updated output can be verified.</div>{error ? <p className="mt-3 text-sm" style={{ color: "var(--accent-negative)" }}>{error}</p> : null}<div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} disabled={rerendering} className="rounded-md border px-3 py-2 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>Cancel</button><button type="button" onClick={onConfirm} disabled={rerendering} className="rounded-md px-3 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-primary)" }}>{rerendering ? "Re-rendering…" : "Create re-rendered revision"}</button></div></div></div>;
}

function SectionHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div><div className="data-label">{eyebrow}</div><h3 className="mt-1 text-lg font-semibold" style={{ color: "var(--text-primary)" }}>{title}</h3><p className="mt-1 max-w-3xl text-sm" style={{ color: "var(--text-secondary)" }}>{description}</p></div>;
}

function EmptyData({ title, detail }: { title: string; detail: string }) {
  return <div className="rounded-lg border border-dashed p-5" style={{ borderColor: "var(--border-strong)", color: "var(--text-secondary)" }}><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>{title}</h3><p className="mt-1 text-sm">{detail}</p></div>;
}

function DataCard({ label, value }: { label: string; value: unknown }) {
  return <article className="rounded-lg border p-4" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}><h3 className="font-semibold" style={{ color: "var(--text-primary)" }}>{titleCase(label)}</h3><div className="mt-2"><DataTree value={value} /></div></article>;
}

function DataTree({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || value === undefined) return <span style={{ color: "var(--text-muted)" }}>—</span>;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return <span className="whitespace-pre-wrap text-sm" style={{ color: "var(--text-primary)" }}>{String(value)}</span>;
  if (depth > 4) return <pre className="mono overflow-x-auto text-xs" style={{ color: "var(--text-secondary)" }}>{JSON.stringify(value, null, 2)}</pre>;
  if (Array.isArray(value)) return <ul className="grid gap-2">{value.slice(0, 50).map((item, index) => <li key={index} className="rounded border p-2" style={{ borderColor: "var(--border-subtle)" }}><DataTree value={item} depth={depth + 1} /></li>)}{value.length > 50 ? <li className="text-xs" style={{ color: "var(--text-muted)" }}>… {value.length - 50} additional items omitted from this compact view</li> : null}</ul>;
  const record = toRecord(value);
  return <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-[minmax(8rem,.45fr)_minmax(0,1fr)]">{Object.entries(record).slice(0, 80).map(([key, item]) => <div key={key} className="contents"><dt className="text-xs font-medium" style={{ color: "var(--text-muted)" }}>{titleCase(key)}</dt><dd className="min-w-0"><DataTree value={item} depth={depth + 1} /></dd></div>)}</dl>;
}

function collectLegacyMappings(sources: Array<Record<string, unknown>>): Array<[string, unknown]> {
  const names = ["zig_pillar_name", "zig_capability_id", "zig_capability_name", "zig_activity_1", "zig_technology_1", "cref_goal", "cref_objective", "cref_technique", "cref_approach", "cref_effect", "cref_mitigation_id", "cref_mitigation_name", "nist_800_53_controls", "csa_name", "mitre_mitigations", "mitre_analytics", "d3fend_countermeasure_1", "d3fend_countermeasure_2"];
  const items: Array<[string, unknown]> = [];
  for (const name of names) {
    const value = getValue(sources, [name]);
    if (value !== undefined && value !== null && value !== "") items.push([name, value]);
  }
  return items;
}
