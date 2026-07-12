import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ReportDetail as ReportDetailType, ReportSummary } from "../types";
import { fetchReportPdf, getReport, getReportMarkdown } from "../api/client";

interface ReportDetailProps {
  report: ReportSummary;
}

type Tab = "report" | "json";

/** Main panel: tab strip (rendered markdown / raw JSON) + PDF export for one report. */
export default function ReportDetailView({ report }: ReportDetailProps) {
  const [tab, setTab] = useState<Tab>("report");
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [json, setJson] = useState<ReportDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setMarkdown(null);
    setJson(null);

    Promise.all([getReportMarkdown(report.report_id), getReport(report.report_id)])
      .then(([md, j]) => {
        if (cancelled) return;
        setMarkdown(md);
        setJson(j);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load report.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [report.report_id]);

  async function handleExportPdf() {
    setExporting(true);
    try {
      const blob = await fetchReportPdf(report.report_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.report_id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to export PDF.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <header
        className="flex flex-wrap items-center justify-between gap-3 border-b px-6 py-4"
        style={{ borderColor: "var(--border-default)" }}
      >
        <div>
          <div className="data-label">{report.technique_id}</div>
          <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
            {report.technique_name}
          </h2>
        </div>
        <button
          type="button"
          onClick={handleExportPdf}
          disabled={exporting}
          className="rounded-md px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
          style={{ backgroundColor: "var(--accent-secondary)" }}
        >
          {exporting ? "Exporting…" : "Export PDF"}
        </button>
      </header>

      <div
        className="flex gap-1 border-b px-6 print-hide"
        style={{ borderColor: "var(--border-default)" }}
      >
        {(["report", "json"] as Tab[]).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className="border-b-2 px-3 py-2 text-sm font-medium transition-colors"
            style={{
              borderColor: tab === t ? "var(--accent-primary)" : "transparent",
              color: tab === t ? "var(--text-primary)" : "var(--text-secondary)",
            }}
          >
            {t === "report" ? "Report" : "Raw JSON"}
          </button>
        ))}
      </div>

      <div className="custom-scrollbar flex-1 overflow-y-auto px-6 py-6">
        {loading && <p style={{ color: "var(--text-secondary)" }}>Loading…</p>}
        {error && (
          <p className="mono" style={{ color: "var(--accent-negative)" }}>
            {error}
          </p>
        )}
        {!loading && !error && tab === "report" && markdown !== null && (
          <article className="markdown-body max-w-none">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
          </article>
        )}
        {!loading && !error && tab === "json" && json !== null && (
          <pre
            className="mono overflow-x-auto rounded-md border p-4 text-xs"
            style={{ backgroundColor: "var(--bg-surface)", borderColor: "var(--border-default)" }}
          >
            {JSON.stringify(json, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
