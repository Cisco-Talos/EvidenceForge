import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Sparkles } from "lucide-react";
import type { StudioApi } from "./api";
import type { components } from "./generated/studio";

import { Help } from "./components";

type Info = components["schemas"]["ArtifactInfo"];
type Preview = components["schemas"]["ReleaseNotesPreview"];

export function ReleaseNotesField({ itemId, revision, value, onChange, onReviewed, disabled, api, help }: {
  itemId: string; revision: string; value: string; onChange: (value: string) => void;
  onReviewed: (info: Info) => void; disabled: boolean; api: StudioApi; help?: string;
}) {
  const [pending, setPending] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState("");
  const live = useRef(false);
  const edits = useRef(0);
  const sourceKey = `${itemId}:${revision}`;
  const current = useRef({ sourceKey, value });
  current.current = { sourceKey, value };
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => { setPreview(null); setError(""); }, [sourceKey]);

  async function suggest() {
    if (pending || disabled) return;
    const snapshot = current.current;
    const editRevision = edits.current;
    const stillCurrent = () => live.current && current.current.sourceKey === snapshot.sourceKey && current.current.value === snapshot.value && edits.current === editRevision;
    setPending(true); setError(""); setPreview(null);
    try {
      const reviewed = await api.request<Info>(`/v1/items/${itemId}/lifecycle`);
      if (!stillCurrent()) return;
      if (reviewed.lifecycle?.status !== "draft") throw new Error("Create a draft before editing release notes.");
      onReviewed(reviewed);
      const proposed = await api.request<Preview>("/v1/assist/release-notes", "POST", { item_id: itemId, expected_digest: reviewed.digest, notes: snapshot.value }, 130000);
      if (stillCurrent()) setPreview(proposed);
    } catch (failure) { if (stillCurrent()) setError(String(failure)); }
    finally { if (live.current) setPending(false); }
  }

  return <div className="release-notes-field">
    <div className="assisted-field-heading"><label htmlFor={`release-notes-${itemId}`}>Release notes</label>{help && <Help text={help} />}<button type="button" className="icon-button ai-suggestion" aria-label="Suggest release notes with AI" title="Ask AI to draft release notes from available parent comparisons" disabled={disabled || pending} onClick={() => void suggest()}>{pending ? <LoaderCircle size={16} className="spinner" /> : <Sparkles size={16} />}</button></div>
    <textarea id={`release-notes-${itemId}`} rows={4} value={value} disabled={disabled} maxLength={65536} onChange={(event) => { edits.current++; setPreview(null); setError(""); onChange(event.target.value); }} />
    {pending && <p className="muted small" role="status">Drafting a suggestion… You can keep editing your notes.</p>}
    {error && <p className="field-error" role="alert">{error} You can always write notes yourself.</p>}
    {preview && <div className="release-notes-preview" role="region" aria-label="AI release notes preview"><label>Suggested release notes<textarea rows={4} disabled={disabled} value={preview.release_notes} maxLength={65536} onChange={(event) => setPreview({ ...preview, release_notes: event.target.value })} /></label><p className="muted small">Review and edit this suggestion. Using it fills your notes; Save notes remains a separate step.</p>{!!preview.findings?.length && <ul className="muted small">{preview.findings.map((finding, index) => <li key={index}>{finding}</li>)}</ul>}<div className="job-actions"><button type="button" className="button-quiet" disabled={disabled} onClick={() => setPreview(null)}>Dismiss</button><button type="button" className="button-quiet" disabled={disabled || !preview.release_notes.trim()} onClick={() => { edits.current++; onChange(preview.release_notes); setPreview(null); }}>Use suggestion</button></div></div>}
  </div>;
}
