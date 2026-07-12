import type {
  AnalyzeResponse,
  JobStatusResponse,
  Provider,
  ReportDetail,
  ReportSummary,
} from "../types";

/**
 * Minimal fetch-based API client for the MITRE CSD-H FastAPI backend, mounted
 * at /api on the same origin as this app. Every function below maps 1:1 to a
 * documented endpoint in the API contract — see the project brief.
 */

async function parseJsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = (body as { detail?: string })?.detail ?? JSON.stringify(body);
    } catch {
      detail = await res.text().catch(() => "");
    }
    throw new Error(detail || `Request failed with status ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export interface AnalyzeArgs {
  text?: string;
  file?: File;
  provider?: Provider;
}

/** POST /api/analyze — multipart/form-data with either "text" or "file", plus optional "provider". */
export async function analyze(args: AnalyzeArgs): Promise<AnalyzeResponse> {
  const form = new FormData();
  if (args.file) {
    form.append("file", args.file);
  } else if (args.text) {
    form.append("text", args.text);
  }
  if (args.provider) {
    form.append("provider", args.provider);
  }

  const res = await fetch("/api/analyze", {
    method: "POST",
    body: form,
  });
  return parseJsonOrThrow<AnalyzeResponse>(res);
}

/** GET /api/jobs/{job_id} */
export async function getJobStatus(jobId: string): Promise<JobStatusResponse> {
  const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
  return parseJsonOrThrow<JobStatusResponse>(res);
}

/** GET /api/reports */
export async function listReports(): Promise<ReportSummary[]> {
  const res = await fetch("/api/reports");
  return parseJsonOrThrow<ReportSummary[]>(res);
}

/** GET /api/reports/{report_id} */
export async function getReport(reportId: string): Promise<ReportDetail> {
  const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
  return parseJsonOrThrow<ReportDetail>(res);
}

/** GET /api/reports/{report_id}/markdown */
export async function getReportMarkdown(reportId: string): Promise<string> {
  const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}/markdown`);
  if (!res.ok) {
    throw new Error(`Failed to load report markdown (status ${res.status})`);
  }
  return res.text();
}

/** POST /api/reports/{report_id}/pdf — returns a PDF blob for download. */
export async function fetchReportPdf(reportId: string): Promise<Blob> {
  const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}/pdf`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`Failed to generate PDF (status ${res.status})`);
  }
  return res.blob();
}

/** GET /api/health */
export async function getHealth(): Promise<{ status: string; graph_nodes: number; graph_edges: number }> {
  const res = await fetch("/api/health");
  return parseJsonOrThrow(res);
}
