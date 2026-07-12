import { useRef, useState } from "react";
import type { Provider } from "../types";
import { analyze } from "../api/client";

interface InputViewProps {
  onJobStarted: (jobId: string) => void;
}

const PROVIDER_OPTIONS: { value: Provider; label: string }[] = [
  { value: "", label: "Server default" },
  { value: "local", label: "Local" },
  { value: "openai", label: "OpenAI" },
  { value: "gemini", label: "Gemini" },
  { value: "none", label: "Heuristic (no LLM)" },
];

const ACCEPTED_EXTENSIONS = [".xlsx", ".csv"];

/** Input view: paste freeform threat-intel text OR upload an .xlsx/.csv file, pick a provider, analyze. */
export default function InputView({ onJobStarted }: InputViewProps) {
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [provider, setProvider] = useState<Provider>("");
  const [isDragging, setIsDragging] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const canSubmit = (text.trim().length > 0 || file !== null) && !submitting;

  function handleFileChange(f: File | null) {
    setFile(f);
    if (f) setText(""); // file and text are mutually exclusive per the API contract
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) handleFileChange(dropped);
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await analyze({
        text: file ? undefined : text.trim() || undefined,
        file: file ?? undefined,
        provider: provider || undefined,
      });
      onJobStarted(res.job_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to start analysis.");
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-4 py-10">
      <div>
        <h1 className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>
          New Threat Assessment
        </h1>
        <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          Paste freeform threat-intel text, or upload a vulnerability assessment spreadsheet.
        </p>
      </div>

      <div
        className="rounded-lg border p-4"
        style={{ backgroundColor: "var(--bg-surface)", borderColor: "var(--border-default)" }}
      >
        <label className="data-label mb-2 block">Paste threat-intel text</label>
        <textarea
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            if (e.target.value) setFile(null);
          }}
          disabled={file !== null}
          rows={10}
          placeholder="Paste a freeform threat-intel narrative, IOC list, or vulnerability description here..."
          className="w-full resize-y rounded-md border p-3 text-sm outline-none disabled:opacity-50"
          style={{
            backgroundColor: "var(--bg-base)",
            borderColor: "var(--border-default)",
            color: "var(--text-primary)",
          }}
        />
      </div>

      <div className="flex items-center gap-3">
        <div className="h-px flex-1" style={{ backgroundColor: "var(--border-default)" }} />
        <span className="data-label">or</span>
        <div className="h-px flex-1" style={{ backgroundColor: "var(--border-default)" }} />
      </div>

      <div
        className="rounded-lg border p-4"
        style={{ backgroundColor: "var(--bg-surface)", borderColor: "var(--border-default)" }}
      >
        <label className="data-label mb-2 block">Upload assessment file (.xlsx / .csv)</label>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed p-8 text-center transition-colors"
          style={{
            borderColor: isDragging ? "var(--accent-primary)" : "var(--border-strong)",
            backgroundColor: isDragging ? "var(--accent-glow)" : "var(--bg-base)",
          }}
        >
          {file ? (
            <>
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                {file.name}
              </span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleFileChange(null);
                  if (fileInputRef.current) fileInputRef.current.value = "";
                }}
                className="text-xs underline"
                style={{ color: "var(--accent-negative)" }}
              >
                Remove
              </button>
            </>
          ) : (
            <>
              <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Drag & drop a file here, or click to browse
              </span>
              <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                Accepted: {ACCEPTED_EXTENSIONS.join(", ")}
              </span>
            </>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED_EXTENSIONS.join(",")}
            className="hidden"
            onChange={(e) => handleFileChange(e.target.files?.[0] ?? null)}
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <label className="data-label" htmlFor="provider-select">
            LLM provider
          </label>
          <select
            id="provider-select"
            value={provider}
            onChange={(e) => setProvider(e.target.value as Provider)}
            className="rounded-md border px-3 py-1.5 text-sm outline-none"
            style={{
              backgroundColor: "var(--bg-surface)",
              borderColor: "var(--border-default)",
              color: "var(--text-primary)",
            }}
          >
            {PROVIDER_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={handleSubmit}
          disabled={!canSubmit}
          className="rounded-md px-5 py-2 text-sm font-semibold text-white transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
          style={{ backgroundColor: "var(--accent-primary)" }}
        >
          {submitting ? "Starting…" : "Analyze"}
        </button>
      </div>

      {error && (
        <div
          className="rounded-md border px-4 py-3 text-sm"
          style={{
            borderColor: "var(--accent-negative)",
            backgroundColor: "var(--accent-negative-glow)",
            color: "var(--accent-negative)",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}
