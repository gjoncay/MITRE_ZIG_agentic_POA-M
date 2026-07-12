export type Provider = "" | "local" | "openai" | "gemini" | "none";

export type JobStatus = "pending" | "running" | "done" | "failed";

export interface AnalyzeResponse {
  job_id: string;
}

export interface JobStatusResponse {
  status: JobStatus;
  stage: string;
  error: string | null;
  report_ids: string[];
}

export interface ReportSummary {
  report_id: string;
  technique_id: string;
  technique_name: string;
  finding_count: number;
  severity_breakdown: Record<string, number>;
  qa_verdict: "PASS" | "FLAG";
  generated_date: string;
}

// The full report JSON shape is not fully specified by the backend contract
// beyond being "the full parsed JSON content" — treat it as an open record
// and render it via JSON.stringify in the Raw JSON tab.
export type ReportDetail = Record<string, unknown>;
