import { useCallback, useEffect, useRef, useState } from "react";
import { createRun, getLocalModels } from "../api/client";

interface InputViewProps {
  onJobStarted: (jobId: string) => void;
}

const ACCEPTED_EXTENSIONS = [".xlsx", ".xls", ".csv", ".json", ".txt", ".md"];

/** A run may contain many artifacts/observations and each observation may resolve to
 * more than one ATT&CK technique. File-type validation remains authoritative on the backend. */
export default function InputView({ onJobStarted }: InputViewProps) {
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState("");
  const [modelsLoading, setModelsLoading] = useState(true);
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [modelSource, setModelSource] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadModels = useCallback(async () => {
    setModelsLoading(true);
    setModelsError(null);
    try {
      const inventory = await getLocalModels();
      setModels(inventory.models);
      setModel((current) => current && inventory.models.includes(current) ? current : inventory.models[0] || "");
      setModelSource(inventory.source === "ollama" ? "Ollama" : inventory.source === "openai_compatible" ? "OpenAI-compatible local server" : null);
      if (inventory.error) setModelsError(inventory.error);
      else if (!inventory.configured || inventory.models.length === 0) setModelsError("No local model is configured or available. Start your local model server, then refresh this list.");
    } catch (caught) {
      setModels([]);
      setModel("");
      setModelsError(caught instanceof Error ? caught.message : "Unable to discover local models.");
    } finally {
      setModelsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadModels();
  }, [loadModels]);

  const canSubmit = (text.trim().length > 0 || file !== null) && !submitting && !modelsLoading && Boolean(model);

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
      const run = await createRun({
        text: file ? undefined : text.trim() || undefined,
        file: file ?? undefined,
        provider: "local",
        model,
      });
      onJobStarted(run.id);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to start analysis.");
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
          Paste a finding or threat-intel artifact, or upload a CSV/XLSX vulnerability or assessment export, text/Markdown, or STIX-compatible JSON.
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
        <label className="data-label mb-2 block">Upload a supported artifact</label>
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

      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--bg-surface)", borderColor: "var(--border-default)" }}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <label className="data-label block" htmlFor="local-model-select">Local model</label>
            <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>Only models exposed by this server's configured local endpoint are available. Submitted evidence is not sent to a cloud provider.</p>
          </div>
          <button type="button" onClick={() => void loadModels()} disabled={modelsLoading} className="rounded-md border px-3 py-1.5 text-sm font-medium disabled:opacity-50" style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}>{modelsLoading ? "Checking models…" : "Refresh models"}</button>
        </div>
        <select
          id="local-model-select"
          value={model}
          onChange={(event) => setModel(event.target.value)}
          disabled={modelsLoading || models.length === 0}
          className="mt-3 w-full rounded-md border px-3 py-2 text-sm outline-none disabled:opacity-50"
          style={{ backgroundColor: "var(--bg-base)", borderColor: "var(--border-default)", color: "var(--text-primary)" }}
        >
          {models.length === 0 ? <option value="">{modelsLoading ? "Discovering local models…" : "No local models found"}</option> : null}
          {models.map((availableModel) => <option key={availableModel} value={availableModel}>{availableModel}</option>)}
        </select>
        {modelSource ? <p className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>Discovered through {modelSource}.</p> : null}
        {modelsError ? <p className="mt-2 text-sm" style={{ color: models.length > 0 ? "var(--accent-warning)" : "var(--accent-negative)" }}>{modelsError}</p> : null}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-4">
        <button
          type="button"
          onClick={handleSubmit}
          disabled={!canSubmit}
          className="rounded-md px-5 py-2 text-sm font-semibold text-white transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
          style={{ backgroundColor: "var(--accent-primary)" }}
        >
          {submitting ? "Starting…" : "Analyze locally"}
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
