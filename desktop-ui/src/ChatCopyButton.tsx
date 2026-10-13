import { useEffect, useState } from "react";
import { Check, Copy } from "lucide-react";
import { writePathToClipboard } from "./CopyPathButton";

export function ChatCopyButton({ text, label = "Copy message", onError }: { text: string | (() => string); label?: string; onError?: (error: string) => void }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => { if (!copied) return; const timer = setTimeout(() => setCopied(false), 1800); return () => clearTimeout(timer); }, [copied]);
  async function copy() {
    const focused = document.activeElement as HTMLElement | null;
    try { await writePathToClipboard(typeof text === "function" ? text() : text); setCopied(true); }
    catch (error) { onError?.(String(error)); }
    finally { focused?.focus({ preventScroll: true }); }
  }
  return <button type="button" className="chat-copy icon-button" aria-label={label} title={copied ? "Copied" : label} onClick={() => void copy()}>{copied ? <Check size={14} /> : <Copy size={14} />}<span className="sr-only">{copied ? "Copied" : label}</span></button>;
}
