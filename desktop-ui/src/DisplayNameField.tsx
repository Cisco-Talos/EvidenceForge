import { useEffect, useId, useRef, useState } from "react";
import { LoaderCircle, Sparkles } from "lucide-react";
import type { StudioApi } from "./api";
import type { components } from "./generated/studio";

import { Help } from "./components";

type Context = components["schemas"]["DisplayNameContext"];
export type DisplayNameSource = Omit<components["schemas"]["DisplayNameRequest"], "context"> & {
  context?: Pick<Context, "kind" | "name"> & Partial<Pick<Context, "description" | "details">>;
};
type Suggestion = components["schemas"]["DisplayNameSuggestion"];

export function DisplayNameField({ value, onChange, label, placeholder, disabled, api, source, prepareSource, allowReplacement = false, autoFocus = false, help, previewRequired = false }: {
  value: string; onChange: (value: string) => void; label: string; placeholder: string;
  disabled: boolean; api: StudioApi; source: DisplayNameSource | null;
  prepareSource?: () => Promise<DisplayNameSource>; allowReplacement?: boolean; autoFocus?: boolean; help?: string; previewRequired?: boolean;
}) {
  const inputId = useId();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [suggested, setSuggested] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const current = useRef({ value, key: JSON.stringify(source) });
  const edits = useRef(0);
  const live = useRef(false);
  current.current = { value, key: JSON.stringify(source) };
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => { setError(""); setSuggested(false); setPreview(null); }, [current.current.key]);

  async function suggest() {
    if ((!source && !prepareSource) || pending || disabled || (!allowReplacement && value.trim())) return;
    const snapshot = current.current;
    const revision = edits.current;
    setPending(true); setError(""); setSuggested(false);
    const stillCurrent = () => live.current && current.current.key === snapshot.key && current.current.value === snapshot.value && edits.current === revision;
    try {
      const captured = prepareSource ? await prepareSource() : source;
      if (!stillCurrent()) return;
      const result = await api.request<Suggestion>("/v1/assist/display-name", "POST", captured, 130000);
      if (stillCurrent()) { if (previewRequired) setPreview(result.display_name); else { onChange(result.display_name); setSuggested(true); } }
    } catch (failure) { if (stillCurrent()) setError(String(failure)); }
    finally { if (live.current) setPending(false); }
  }

  return <div className="display-name-field">
    <div className="modal-field">
      <div className="assisted-field-heading"><label htmlFor={inputId}>Display name · optional</label>{help && <Help text={help} />}
        {(allowReplacement || !value.trim() || pending) && <button type="button" className="icon-button ai-suggestion" aria-label="Suggest display name with AI" title="Ask AI for a display name" disabled={disabled || pending || (!source && !prepareSource)} onClick={() => void suggest()}>{pending ? <LoaderCircle size={16} className="spinner" /> : <Sparkles size={16} />}</button>}
      </div>
      <input id={inputId} autoFocus={autoFocus} aria-label={label} value={value} disabled={disabled} placeholder={placeholder} onChange={(event) => { edits.current++; setError(""); setSuggested(false); setPreview(null); onChange(event.target.value); }} />
    </div>
    {pending && <p className="muted small" role="status">Suggesting a display name… You can keep typing.</p>}
    {suggested && <p className="muted small" role="status">AI suggestion. Review or edit it before saving.</p>}
    {preview !== null && <div className="suggestion-preview" role="region" aria-label="AI display name preview"><label>Suggested display name<input value={preview} onChange={(event) => setPreview(event.target.value)} /></label><div className="job-actions"><button type="button" className="button-quiet" onClick={() => setPreview(null)}>Dismiss</button><button type="button" className="button-quiet" disabled={disabled || !preview.trim()} onClick={() => { edits.current++; onChange(preview); setPreview(null); }}>Use suggestion</button></div></div>}
    {error && <p className="field-error" role="alert">{error} You can always enter a name yourself.</p>}
  </div>;
}
