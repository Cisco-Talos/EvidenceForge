import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { Download, FileCode2, X } from "lucide-react";
import type { ExportProgress, StudioApi, TextPreview } from "./api";
import { CopyPathButton } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { ChatMarkdown } from "./ChatMarkdown";

export interface BundleFiles {
  root: string;
  files: { path: string; size: number }[];
  truncated: boolean;
}

export function bundleFileUrl(jobId: string, path: string, kind: "jobs" | "bundles" | "items" | "environment" = "jobs"): string {
  return `/v1/${kind}/${jobId}/files/${path.split("/").map(encodeURIComponent).join("/")}`;
}

function languageFor(path: string, text: string): string {
  if (/\.(json|jsonl)$/i.test(path)) return "json";
  if (/\.(yaml|yml)$/i.test(path)) return "yaml";
  if (/\.(md|markdown)$/i.test(path)) return "markdown";
  if (/\.(eml|email)$/i.test(path)) return "email";
  if (/\.xml$/i.test(path) || /^\s*(?:<\?xml\b|<Events?\b)/.test(text)) return "xml";
  return "text";
}

function highlightTokens(value: string, language: string): React.ReactNode[] {
  const pattern = language === "json"
    ? /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|\b(?:true|false|null|\d+(?:\.\d+)?)\b/g
    : /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:true|false|null|\d+(?:\.\d+)?)\b/g;
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  for (const match of value.matchAll(pattern)) {
    const index = match.index;
    if (index > cursor) parts.push(value.slice(cursor, index));
    const token = match[0];
    const type = token.startsWith('"') && language === "json" && /^\s*:/.test(value.slice(index + token.length))
      ? "key" : /^['"]/.test(token) ? "string" : /^\d/.test(token) ? "number" : "keyword";
    parts.push(<span className={`syntax-${type}`} key={index}>{token}</span>);
    cursor = index + token.length;
  }
  if (cursor < value.length) parts.push(value.slice(cursor));
  return parts;
}

function highlightedLine(line: string, language: string): React.ReactNode {
  if (language === "xml") {
    const pattern = /<!--.*?-->|<\?.*?\?>|<![^>]*>|<\/?[\w:.-]+|[\w:.-]+(?=\s*=)|"[^"]*"|'[^']*'|\/?>|&(?:#x?[\da-f]+|\w+);/gi;
    const parts: React.ReactNode[] = [];
    let cursor = 0;
    for (const match of line.matchAll(pattern)) {
      if (match.index > cursor) parts.push(line.slice(cursor, match.index));
      const token = match[0];
      const type = token.startsWith("<!--") ? "comment"
        : /^['"]/.test(token) ? "string"
        : token.startsWith("&") || token.startsWith("<?") ? "keyword" : "key";
      parts.push(<span className={`syntax-${type}`} key={match.index}>{token}</span>);
      cursor = match.index + token.length;
    }
    parts.push(line.slice(cursor));
    return parts;
  }
  if (language === "markdown") {
    if (/^\s{0,3}#{1,6}\s/.test(line)) return <span className="syntax-heading">{line}</span>;
    if (/^\s*(```|~~~)/.test(line)) return <span className="syntax-keyword">{line}</span>;
    if (/^\s*(?:[-*+] |\d+\. )/.test(line)) return <span className="syntax-list">{line}</span>;
    return line;
  }
  if (language === "email") {
    const header = line.match(/^([\w-]+:)(.*)$/);
    if (header) return <><span className="syntax-key">{header[1]}</span>{header[2]}</>;
    if (line.startsWith("--")) return <span className="syntax-keyword">{line}</span>;
    return line;
  }
  if (language === "yaml") {
    if (/^\s*#/.test(line)) return <span className="syntax-comment">{line}</span>;
    const key = line.match(/^(\s*(?:-\s+)?[\w.-]+:)(.*)$/);
    if (key) return <><span className="syntax-key">{key[1]}</span>{highlightTokens(key[2], language)}</>;
  }
  return language === "json" || language === "yaml" ? highlightTokens(line, language) : line;
}

export function BundleFileBrowser({ jobId, files, api, onClose, onError, kind = "jobs" }: {
  jobId: string; files: BundleFiles; api: StudioApi; kind?: "jobs" | "bundles" | "items" | "environment";
  onClose: () => void; onError: (message: string) => void;
}) {
  const first = ["GROUND_TRUTH.md", "RESOLVED_SCENARIO.yaml", "RESOLVED_SCENARIO.yml", "GENERATION_MANIFEST.json"]
    .map((name) => files.files.find((entry) => entry.path.split("/").slice(-1)[0]?.toLowerCase() === name.toLowerCase())?.path)
    .find(Boolean) || files.files[0]?.path || null;
  const [selected, setSelected] = useState<string | null>(first);
  const [preview, setPreview] = useState<TextPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState<ExportProgress | null>(null);
  const [savedExport, setSavedExport] = useState<string | null>(null);
  const [showSource, setShowSource] = useState(false);

  async function saveSelectedFile() {
    if (!selected) return;
    setExporting(true);
    setExportProgress(null);
    setSavedExport(null);
    try {
      const result = await api.download(bundleFileUrl(jobId, selected, kind), selected.split("/").slice(-1)[0] || "file", setExportProgress);
      if (result.status === "saved") setSavedExport(result.path);
    } catch (reason) { onError(String(reason)); }
    finally { setExporting(false); setExportProgress(null); }
  }

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setPreview(null);
    setShowSource(false);
    setError(null);
    setLoading(true);
    void api.readTextPreview(bundleFileUrl(jobId, selected, kind))
      .then((result) => { if (!cancelled) setPreview(result); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, jobId, kind, selected]);

  const lines = preview?.text.split("\n").slice(0, 4000) || [];
  const language = languageFor(selected || "", preview?.text || "");
  const title = kind === "items" ? "Source YAML" : kind === "environment" ? "Configuration overlay" : "Bundle files";
  return <div className="modal-backdrop"><div className={`close-modal bundle-browser ${kind === "items" ? "source-file-browser" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
    <div className="bundle-browser-heading"><div><h2>{title}</h2><div className="path-with-copy"><span className="path-value source-path" title={files.root}>{files.root}</span><CopyPathButton path={files.root} label={kind === "items" ? "Copy source folder path" : "Copy bundle path"} onError={onError} /></div></div><button className="icon-button" aria-label={`Close ${title.toLowerCase()}`} onClick={onClose}><X size={18} /></button></div>
    <div className="bundle-browser-layout"><nav className="bundle-file-list" aria-label="Bundle file list">{files.files.length ? files.files.map((file) => <button key={file.path} className={`bundle-file-row ${selected === file.path ? "selected" : ""}`} onClick={() => setSelected(file.path)}><FileCode2 size={15} /><span title={file.path}>{file.path}</span><small>{file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`}</small></button>) : <p className="muted">This bundle has no files yet.</p>}{files.truncated && <p className="muted">Showing the first 500 files.</p>}</nav>
      <div className="bundle-preview"><div className="bundle-preview-heading"><div className="path-with-copy bundle-selected-path"><strong className="path-value" title={selected || undefined}>{selected || "Choose a file"}</strong>{selected && <CopyPathButton path={`${files.root.replace(/[\\/]$/, "")}/${selected}`} label="Copy file path" onError={onError} />}</div>{language === "markdown" && <button className="button-quiet" aria-pressed={showSource} onClick={() => setShowSource(!showSource)}>{showSource ? "Rendered view" : "View source"}</button>}{selected && <button className="button-quiet" disabled={exporting} onClick={() => void saveSelectedFile()}><Download size={15} /> {exporting ? "Saving…" : isTauri() ? "Save a copy" : "Download file"}</button>}</div>
        {exporting && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}
        {savedExport && <div className="path-with-copy bundle-preview-message"><span className="path-value muted" title={savedExport}>Saved to {savedExport}</span><CopyPathButton path={savedExport} label="Copy saved file path" onError={onError} /></div>}
        {loading ? <p className="muted bundle-preview-message">Loading preview…</p> : error ? <p className="error-text bundle-preview-message">{error}</p> : preview?.binary ? <p className="muted bundle-preview-message">This file is binary. {isTauri() ? "Save a copy" : "Download it"} to inspect it.</p> : selected && preview ? <>{language === "markdown" && !showSource ? <article className="bundle-markdown" aria-label={`Preview of ${selected}`}><ChatMarkdown text={lines.join("\n")} /></article> : <pre className={`bundle-source language-${language}`} aria-label={`Preview of ${selected}`}>{lines.map((line, index) => <div className="bundle-source-line" key={index}><span className="line-number" aria-hidden="true">{index + 1}</span><span>{highlightedLine(line, language)}</span></div>)}</pre>}{(preview.truncated || preview.text.split("\n").length > lines.length) && <p className="bundle-preview-limit">Showing the first 256 KB or 4,000 lines. {isTauri() ? "Save a copy" : "Download the file"} for the rest.</p>}</> : <p className="muted bundle-preview-message">Select a file to view it.</p>}
      </div>
    </div>
  </div></div>;
}
