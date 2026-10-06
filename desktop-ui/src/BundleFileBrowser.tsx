import { useEffect, useLayoutEffect, useRef, useState } from "react";
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

type FileKind = "jobs" | "bundles" | "items" | "environment" | "declarations";

export function bundleFileUrl(jobId: string, path: string, kind: FileKind = "jobs"): string {
  const prefix = kind === "declarations" ? `/v1/environment/${jobId}/declarations` : `/v1/${kind}/${jobId}`;
  return `${prefix}/files/${path.split("/").map(encodeURIComponent).join("/")}`;
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

export function BundleFileBrowser({ jobId, files, api, onClose, onError, kind = "jobs", initialLine }: {
  jobId: string; files: BundleFiles; api: StudioApi; kind?: FileKind;
  initialLine?: number | null;
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
  const sourceViewport = useRef<HTMLPreElement>(null);
  const contextLine = useRef<HTMLDivElement>(null);
  const targetLine = initialLine && selected === first ? initialLine : null;
  const selectedSize = files.files.find((file) => file.path === selected)?.size || 0;
  // Read enough captured YAML to locate late declarations; ordinary log previews stay small.
  const previewBytes = targetLine ? Math.min(16 * 1024 * 1024 + 1, Math.max(256 * 1024, selectedSize + 1)) : undefined;

  async function saveSelectedFile() {
    if (!selected) return;
    setExporting(true);
    setExportProgress(null);
    setSavedExport(null);
    try {
      const basename = selected.split("/").slice(-1)[0] || "file";
      const filename = kind === "declarations" ? basename.replace(/^[0-9a-f]{16}-/, "") : basename;
      const result = await api.download(bundleFileUrl(jobId, selected, kind), filename, setExportProgress);
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
    const url = bundleFileUrl(jobId, selected, kind);
    void (previewBytes ? api.readTextPreview(url, previewBytes) : api.readTextPreview(url))
      .then((result) => { if (!cancelled) setPreview(result); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, jobId, kind, selected, previewBytes]);

  const allLines = preview?.text.split("\n") || [];
  const lineAvailable = !!targetLine && targetLine <= allLines.length;
  const firstLine = lineAvailable && targetLine > 4000 ? targetLine - 4 : 0;
  const lines = allLines.slice(firstLine, firstLine + 4000);
  useLayoutEffect(() => {
    const viewport = sourceViewport.current;
    const context = contextLine.current;
    if (!viewport || !context) return;
    viewport.scrollTop = Math.max(0, context.getBoundingClientRect().top - viewport.getBoundingClientRect().top + viewport.scrollTop - 12);
  }, [preview, targetLine, showSource]);
  const language = languageFor(selected || "", preview?.text || "");
  const title = kind === "items" ? "Source YAML" : kind === "environment" ? "Configuration overlay" : kind === "declarations" ? "Declaring YAML" : "Bundle files";
  return <div className="modal-backdrop"><div className={`close-modal bundle-browser ${kind === "items" || kind === "declarations" ? "source-file-browser" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
    <div className="bundle-browser-heading"><div><h2>{title}</h2><div className="path-with-copy"><span className="path-value source-path" title={files.root}>{files.root}</span>{kind !== "declarations" && <CopyPathButton path={files.root} label={kind === "items" ? "Copy source folder path" : "Copy bundle path"} onError={onError} />}</div></div><button className="icon-button" aria-label={`Close ${title.toLowerCase()}`} onClick={onClose}><X size={18} /></button></div>
    <div className="bundle-browser-layout"><nav className="bundle-file-list" aria-label="Bundle file list">{files.files.length ? files.files.map((file) => <button key={file.path} className={`bundle-file-row ${selected === file.path ? "selected" : ""}`} onClick={() => setSelected(file.path)}><FileCode2 size={15} /><span title={file.path}>{file.path}</span><small>{file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`}</small></button>) : <p className="muted">This bundle has no files yet.</p>}{files.truncated && <p className="muted">Showing the first 500 files.</p>}</nav>
      <div className="bundle-preview"><div className="bundle-preview-heading"><div className="path-with-copy bundle-selected-path"><strong className="path-value" title={selected || undefined}>{selected ? kind === "declarations" ? selected.split("/").slice(1).join("/") : selected : "Choose a file"}</strong>{selected && kind !== "declarations" && <CopyPathButton path={`${files.root.replace(/[\\/]$/, "")}/${selected}`} label="Copy file path" onError={onError} />}</div>{language === "markdown" && <button className="button-quiet" aria-pressed={showSource} onClick={() => setShowSource(!showSource)}>{showSource ? "Rendered view" : "View source"}</button>}{selected && <button className="button-quiet" disabled={exporting} onClick={() => void saveSelectedFile()}><Download size={15} /> {exporting ? "Saving…" : isTauri() ? "Save a copy" : "Download file"}</button>}</div>
        {exporting && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}
        {savedExport && <div className="path-with-copy bundle-preview-message"><span className="path-value muted" title={savedExport}>Saved to {savedExport}</span><CopyPathButton path={savedExport} label="Copy saved file path" onError={onError} /></div>}
        {loading ? <p className="muted bundle-preview-message">Loading preview…</p> : error ? <p className="error-text bundle-preview-message">{error}</p> : preview?.binary ? <p className="muted bundle-preview-message">This file is binary. {isTauri() ? "Save a copy" : "Download it"} to inspect it.</p> : selected && preview ? <>{language === "markdown" && !showSource ? <article className="bundle-markdown" aria-label={`Preview of ${selected}`}><ChatMarkdown text={lines.join("\n")} /></article> : <pre ref={sourceViewport} className={`bundle-source language-${language}`} aria-label={`Preview of ${selected}`}>{lines.map((line, index) => <div ref={lineAvailable && index + firstLine + 1 === Math.max(1, targetLine - 3) ? contextLine : undefined} className={`bundle-source-line ${index + firstLine + 1 === targetLine ? "matched-line" : ""}`} aria-label={index + firstLine + 1 === targetLine ? `Matched declaration, line ${targetLine}` : undefined} key={index + firstLine}><span className="line-number" aria-hidden="true">{index + firstLine + 1}</span><span>{highlightedLine(line, language)}</span></div>)}</pre>}{targetLine && <p className="bundle-line-location" role="status">{lineAvailable ? `Declaration at line ${targetLine} · highlighted` : `Line ${targetLine} is outside this preview.`}</p>}{(preview.truncated || allLines.length > lines.length) && <p className="bundle-preview-limit">Showing lines {firstLine + 1}–{firstLine + lines.length}{preview.truncated ? " of a truncated preview" : ` of ${allLines.length}`}. {isTauri() ? "Save a copy" : "Download the file"} for the rest.</p>}</> : <p className="muted bundle-preview-message">Select a file to view it.</p>}
      </div>
    </div>
  </div></div>;
}
