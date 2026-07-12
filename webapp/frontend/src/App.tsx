import { useState } from "react";
import InputView from "./components/InputView";
import ProgressView from "./components/ProgressView";
import ReportBrowser from "./components/ReportBrowser";
import ThemeToggle from "./components/ThemeToggle";

type View =
  | { name: "input" }
  | { name: "progress"; jobId: string }
  | { name: "reports"; focusReportIds?: string[] };

export default function App() {
  const [view, setView] = useState<View>({ name: "reports" });

  return (
    <div className="flex h-screen min-h-0 flex-col" style={{ backgroundColor: "var(--bg-base)" }}>
      <header
        className="flex flex-shrink-0 items-center justify-between border-b px-6 py-3 print-hide"
        style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}
      >
        <div className="flex items-center gap-3">
          <h1 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
            MITRE CSD-H
          </h1>
          <span className="data-label">Threat Assessment</span>
        </div>
        <nav className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setView({ name: "input" })}
            className="rounded-md border px-3 py-1.5 text-sm font-medium"
            style={{
              borderColor: view.name === "input" ? "var(--accent-primary)" : "var(--border-default)",
              color: view.name === "input" ? "var(--accent-primary)" : "var(--text-secondary)",
              backgroundColor: "var(--bg-surface)",
            }}
          >
            New Analysis
          </button>
          <button
            type="button"
            onClick={() => setView({ name: "reports" })}
            className="rounded-md border px-3 py-1.5 text-sm font-medium"
            style={{
              borderColor: view.name === "reports" ? "var(--accent-primary)" : "var(--border-default)",
              color: view.name === "reports" ? "var(--accent-primary)" : "var(--text-secondary)",
              backgroundColor: "var(--bg-surface)",
            }}
          >
            Reports
          </button>
          <ThemeToggle />
        </nav>
      </header>

      <div className="min-h-0 flex-1 overflow-auto">
        {view.name === "input" && (
          <InputView onJobStarted={(jobId) => setView({ name: "progress", jobId })} />
        )}
        {view.name === "progress" && (
          <ProgressView
            jobId={view.jobId}
            onDone={(reportIds) => setView({ name: "reports", focusReportIds: reportIds })}
            onBack={() => setView({ name: "input" })}
          />
        )}
        {view.name === "reports" && <ReportBrowser focusReportIds={view.focusReportIds} />}
      </div>

      <footer
        className="flex-shrink-0 border-t px-6 py-2 text-center text-xs print-hide"
        style={{ borderColor: "var(--border-default)", color: "var(--text-muted)" }}
      >
        Raw report files are also available directly on disk under reports/ for inspection in any
        text editor.
      </footer>
    </div>
  );
}
