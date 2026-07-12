import { useEffect, useRef, useState } from "react";
import type { JobStatusResponse } from "../types";
import { getJobStatus } from "../api/client";

interface ProgressViewProps {
  jobId: string;
  onDone: (reportIds: string[]) => void;
  onBack: () => void;
}

const POLL_INTERVAL_MS = 2000;

/** Polls GET /api/jobs/{job_id} every ~2s, showing the current stage until done/failed. */
export default function ProgressView({ jobId, onDone, onBack }: ProgressViewProps) {
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const status = await getJobStatus(jobId);
        if (cancelled) return;
        setJob(status);
        setPollError(null);

        if (status.status === "done") {
          onDoneRef.current(status.report_ids);
          return;
        }
        if (status.status === "failed") {
          return; // stop polling, error is rendered below
        }
        timer = setTimeout(poll, POLL_INTERVAL_MS);
      } catch (e) {
        if (cancelled) return;
        setPollError(e instanceof Error ? e.message : "Failed to check job status.");
        timer = setTimeout(poll, POLL_INTERVAL_MS);
      }
    }

    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  const failed = job?.status === "failed";

  return (
    <div className="mx-auto flex w-full max-w-2xl flex-col items-center gap-6 px-4 py-24 text-center">
      {!failed ? (
        <>
          <div
            className="h-10 w-10 animate-spin rounded-full border-4"
            style={{
              borderColor: "var(--border-default)",
              borderTopColor: "var(--accent-primary)",
            }}
          />
          <div>
            <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
              {job?.stage ? `${job.stage}…` : "Starting analysis…"}
            </h2>
            <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
              Job {jobId}
            </p>
          </div>
          {pollError && (
            <p className="text-xs" style={{ color: "var(--accent-warning)" }}>
              {pollError} — retrying…
            </p>
          )}
        </>
      ) : (
        <>
          <div
            className="flex h-10 w-10 items-center justify-center rounded-full text-lg font-bold"
            style={{ backgroundColor: "var(--accent-negative-glow)", color: "var(--accent-negative)" }}
          >
            !
          </div>
          <div>
            <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
              Analysis failed
            </h2>
            <p
              className="mono mt-2 max-w-lg whitespace-pre-wrap text-sm"
              style={{ color: "var(--accent-negative)" }}
            >
              {job?.error ?? "An unknown error occurred."}
            </p>
          </div>
          <button
            type="button"
            onClick={onBack}
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
          >
            Back to input
          </button>
        </>
      )}
    </div>
  );
}
