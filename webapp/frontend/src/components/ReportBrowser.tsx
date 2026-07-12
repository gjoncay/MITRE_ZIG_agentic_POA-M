import { useEffect, useState } from "react";
import type { ReportSummary } from "../types";
import { listReports } from "../api/client";
import ReportDetailView from "./ReportDetail";

interface ReportBrowserProps {
  focusReportIds?: string[];
}

/** Left sidebar of all reports + main panel showing the selected one. */
export default function ReportBrowser({ focusReportIds }: ReportBrowserProps) {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listReports()
      .then((data) => {
        if (cancelled) return;
        setReports(data);
        const preferred = focusReportIds?.find((id) => data.some((r) => r.report_id === id));
        setSelectedId(preferred ?? data[0]?.report_id ?? null);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load reports.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // Intentionally re-run only when the focus set changes (e.g. a new job just completed).
  }, [focusReportIds]);

  const selected = reports.find((r) => r.report_id === selectedId) ?? null;

  return (
    <div className="flex h-full min-h-0 flex-1">
      <aside
        className="custom-scrollbar w-80 flex-shrink-0 overflow-y-auto border-r"
        style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-sunken)" }}
      >
        <div className="px-4 py-3">
          <h3 className="data-label">Reports ({reports.length})</h3>
        </div>
        {loading && (
          <p className="px-4 text-sm" style={{ color: "var(--text-secondary)" }}>
            Loading…
          </p>
        )}
        {error && (
          <p className="mono px-4 text-sm" style={{ color: "var(--accent-negative)" }}>
            {error}
          </p>
        )}
        {!loading && !error && reports.length === 0 && (
          <p className="px-4 text-sm" style={{ color: "var(--text-secondary)" }}>
            No reports yet. Run an analysis to generate one.
          </p>
        )}
        <ul>
          {reports.map((r) => {
            const isSelected = r.report_id === selectedId;
            const isNew = focusReportIds?.includes(r.report_id);
            return (
              <li key={r.report_id}>
                <button
                  type="button"
                  onClick={() => setSelectedId(r.report_id)}
                  className="flex w-full flex-col gap-1 border-b px-4 py-3 text-left transition-colors"
                  style={{
                    borderColor: "var(--border-subtle)",
                    backgroundColor: isSelected ? "var(--bg-raised)" : "transparent",
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono text-xs" style={{ color: "var(--text-muted)" }}>
                      {r.technique_id}
                    </span>
                    <span
                      className="rounded-full px-2 py-0.5 text-[10px] font-semibold"
                      style={{
                        backgroundColor:
                          r.qa_verdict === "PASS" ? "var(--accent-positive-glow)" : "var(--accent-negative-glow)",
                        color: r.qa_verdict === "PASS" ? "var(--accent-positive)" : "var(--accent-negative)",
                      }}
                    >
                      {r.qa_verdict}
                    </span>
                  </div>
                  <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                    {r.technique_name}
                    {isNew && (
                      <span className="ml-1 text-xs" style={{ color: "var(--accent-primary)" }}>
                        • new
                      </span>
                    )}
                  </span>
                  <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                    {r.finding_count} finding{r.finding_count === 1 ? "" : "s"}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </aside>

      <main className="min-h-0 flex-1 overflow-hidden" style={{ backgroundColor: "var(--bg-base)" }}>
        {selected ? (
          <ReportDetailView report={selected} />
        ) : (
          <div className="flex h-full items-center justify-center">
            <p style={{ color: "var(--text-secondary)" }}>
              {loading ? "Loading reports…" : "Select a report to view its details."}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
