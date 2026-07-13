import { useCallback, useEffect, useState } from "react";
import InputView from "./components/InputView";
import ProgressView from "./components/ProgressView";
import ReportBrowser from "./components/ReportBrowser";
import ReviewQueue from "./components/ReviewQueue";
import RunList from "./components/RunList";
import ThemeToggle from "./components/ThemeToggle";
import { establishBrowserSession, getBrowserSession, type BrowserSession } from "./api/client";

type Route =
  | { name: "new" }
  | { name: "runs" }
  | { name: "progress"; runId: string }
  | { name: "review" }
  | { name: "reports"; reportId?: string; runId?: string };

function parseRoute(location: Location): Route {
  const parts = location.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  const runId = new URLSearchParams(location.search).get("run") ?? undefined;
  if (parts[0] === "new") return { name: "new" };
  if (parts[0] === "runs" && parts[2] === "progress" && parts[1]) return { name: "progress", runId: parts[1] };
  if (parts[0] === "runs") return { name: "runs" };
  if (parts[0] === "review") return { name: "review" };
  if (parts[0] === "reports") return { name: "reports", reportId: parts[1], runId };
  return { name: "reports" };
}

function routePath(route: Route): string {
  switch (route.name) {
    case "new":
      return "/new";
    case "runs":
      return "/runs";
    case "progress":
      return `/runs/${encodeURIComponent(route.runId)}/progress`;
    case "review":
      return "/review";
    case "reports": {
      const base = route.reportId ? `/reports/${encodeURIComponent(route.reportId)}` : "/reports";
      return route.runId ? `${base}?run=${encodeURIComponent(route.runId)}` : base;
    }
  }
}

export default function App() {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location));
  const [browserSession, setBrowserSession] = useState<BrowserSession | null>(null);

  useEffect(() => {
    // Older builds persisted a free-form reviewer name. It is not an
    // authenticated identity and must never populate privileged actions.
    window.localStorage.removeItem("csdh-reviewer-identity");
    let canceled = false;
    void getBrowserSession()
      .then((session) => { if (!canceled) setBrowserSession(session); })
      .catch(() => { if (!canceled) setBrowserSession(null); });
    return () => { canceled = true; };
  }, []);

  useEffect(() => {
    const handlePopState = () => setRoute(parseRoute(window.location));
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback((next: Route, replace = false) => {
    const path = routePath(next);
    if (replace) window.history.replaceState({}, "", path);
    else window.history.pushState({}, "", path);
    setRoute(next);
  }, []);

  const reportsActive = route.name === "reports";
  const runsActive = route.name === "runs" || route.name === "progress";
  const reviewActive = route.name === "review";

  return (
    <div className="flex h-screen min-h-0 flex-col" style={{ backgroundColor: "var(--bg-base)" }}>
      <header
        className="flex flex-shrink-0 flex-wrap items-center justify-between gap-3 border-b px-4 py-3 sm:px-6 print-hide"
        style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}
      >
        <div className="flex items-center gap-3">
          <button type="button" onClick={() => navigate({ name: "reports" })} className="text-left">
            <h1 className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
              MITRE CSD-H
            </h1>
          </button>
          <span className="data-label">Threat Assessment</span>
        </div>
        <nav className="flex flex-wrap items-center gap-2" aria-label="Primary navigation">
          <NavButton active={route.name === "new"} onClick={() => navigate({ name: "new" })}>New Analysis</NavButton>
          <NavButton active={runsActive} onClick={() => navigate({ name: "runs" })}>Runs</NavButton>
          <NavButton active={reviewActive} onClick={() => navigate({ name: "review" })}>Review Queue</NavButton>
          <NavButton active={reportsActive} onClick={() => navigate({ name: "reports" })}>Reports</NavButton>
          <ApiSessionControl session={browserSession} onSessionChange={setBrowserSession} />
          <ThemeToggle />
        </nav>
      </header>

      <div className="min-h-0 flex-1 overflow-auto">
        {route.name === "new" && <InputView onJobStarted={(runId) => navigate({ name: "progress", runId })} />}
        {route.name === "runs" && (
          <RunList
            onNewAnalysis={() => navigate({ name: "new" })}
            onOpenRun={(runId) => navigate({ name: "progress", runId })}
            onOpenReports={(runId) => navigate({ name: "reports", runId })}
          />
        )}
        {route.name === "progress" && (
          <ProgressView
            runId={route.runId}
            onBack={() => navigate({ name: "runs" })}
            onOpenRun={(runId) => navigate({ name: "progress", runId })}
            onOpenReports={(runId, reportId) => navigate({ name: "reports", runId, reportId })}
            onReview={() => navigate({ name: "review" })}
          />
        )}
        {route.name === "review" && (
          <ReviewQueue
            onOpenReport={(reportId) => navigate({ name: "reports", reportId })}
            onOpenRun={(runId) => navigate({ name: "progress", runId })}
          />
        )}
        {route.name === "reports" && (
          <ReportBrowser
            selectedReportId={route.reportId}
            runId={route.runId}
            session={browserSession}
            onSessionChange={setBrowserSession}
            onSelectReport={(reportId) => navigate({ name: "reports", reportId, runId: route.runId })}
            onOpenRun={(runId) => navigate({ name: "progress", runId })}
            onOpenReview={() => navigate({ name: "review" })}
          />
        )}
      </div>

      <footer
        className="flex-shrink-0 border-t px-6 py-2 text-center text-xs print-hide"
        style={{ borderColor: "var(--border-default)", color: "var(--text-muted)" }}
      >
        Run history, review decisions, and report lifecycle state are retained by the service. Downloaded exports remain available from each report.
      </footer>
    </div>
  );
}

function ApiSessionControl({ session, onSessionChange }: { session: BrowserSession | null; onSessionChange: (session: BrowserSession) => void }) {
  const [token, setToken] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  async function connect() {
    setConnecting(true);
    setMessage(null);
    try {
      const established = await establishBrowserSession(token || undefined);
      onSessionChange(established);
      setToken("");
      setMessage(`Connected as ${established.actor}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to establish browser access.");
    } finally {
      setConnecting(false);
    }
  }

  return (
    <details className="relative">
      <summary className="cursor-pointer rounded-md border px-3 py-1.5 text-sm font-medium" style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}>
        {session && session.authenticationMode !== "disabled" ? `Access · ${session.actor}` : "Access"}
      </summary>
      <div className="absolute right-0 z-20 mt-2 w-80 rounded-md border p-3 shadow-lg" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)" }}>
        <label className="data-label mb-1 block" htmlFor="api-session-token">Browser access token</label>
        <input id="api-session-token" type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Required for bearer-token deployments" className="w-full rounded-md border px-2 py-1.5 text-sm" style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }} />
        <p className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>For a trusted-proxy deployment, leave this blank and connect to verify the proxy identity. Tokens are exchanged for an HttpOnly session cookie and are not saved in local storage.</p>
        <button type="button" onClick={() => void connect()} disabled={connecting} className="mt-3 rounded-md px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50" style={{ backgroundColor: "var(--accent-primary)" }}>{connecting ? "Connecting…" : "Connect"}</button>
        {message ? <p className="mt-2 text-xs" style={{ color: message.startsWith("Connected") ? "var(--accent-positive)" : "var(--accent-negative)" }}>{message}</p> : null}
      </div>
    </details>
  );
}

function NavButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-md border px-3 py-1.5 text-sm font-medium"
      style={{
        borderColor: active ? "var(--accent-primary)" : "var(--border-default)",
        color: active ? "var(--accent-primary)" : "var(--text-secondary)",
        backgroundColor: "var(--bg-surface)",
      }}
    >
      {children}
    </button>
  );
}
