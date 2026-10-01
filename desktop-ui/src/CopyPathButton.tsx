import { useEffect, useState } from "react";
import { Check, Copy } from "lucide-react";

async function writePathToClipboard(path: string): Promise<void> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(path);
      return;
    }
  } catch { /* Fall back for WebViews that deny the async clipboard API. */ }
  const field = document.createElement("textarea");
  field.value = path;
  field.readOnly = true;
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.appendChild(field);
  field.select();
  try {
    if (!document.execCommand?.("copy")) throw new Error("Clipboard access is unavailable");
  } finally { field.remove(); }
}

export function CopyPathButton({ path, label = "Copy path", onError }: {
  path: string; label?: string; onError: (message: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timer);
  }, [copied, path]);
  useEffect(() => setCopied(false), [path]);

  async function copy() {
    try {
      await writePathToClipboard(path);
      setCopied(true);
    } catch (error) { onError(`Could not copy path: ${String(error)}`); }
  }

  return <button type="button" className={`copy-path-button ${copied ? "copied" : ""}`}
    aria-label={copied ? "Path copied" : label} title={copied ? "Copied" : label}
    onClick={() => void copy()}>{copied ? <Check size={14} /> : <Copy size={14} />}</button>;
}
