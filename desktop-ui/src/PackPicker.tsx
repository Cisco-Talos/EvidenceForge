import { useState } from "react";
import { Search } from "lucide-react";
import { Modal } from "./Modal";
import type { CatalogItem, ScenarioPackReview, SelectedPack, StudioApi } from "./api";

export function packReference(pack: Pick<SelectedPack, "source" | "publisher" | "type" | "name" | "version" | "location">): string {
  return pack.source === "path" || pack.source === "draft"
    ? pack.location
    : `${pack.source}:${pack.publisher}:${pack.type}:${pack.name}@${pack.version}`;
}

type Mode = "none" | "industries" | "organization";
type PackChoice = { reference: string; label: string; kind: string; author: string; version: string; source: string };

const modes: { value: Mode; label: string }[] = [
  { value: "none", label: "Custom (inline)" },
  { value: "industries", label: "Industry packs" },
  { value: "organization", label: "Organization pack" },
];

function References({ references }: { references: string[] }) {
  return references.length
    ? <ul>{references.map((reference) => <li key={reference}><code>{reference}</code></li>)}</ul>
    : <p className="muted small">Custom (inline)</p>;
}

export function PackPicker({
  api, targetId, currentPacks, packs, suggestion, onClose, onPrepare, onApplied, onReturnFocus,
}: {
  api: StudioApi;
  targetId: string;
  currentPacks?: SelectedPack[];
  packs: CatalogItem[];
  suggestion?: string;
  onClose: () => void;
  onPrepare: (prompt: string) => Promise<void>;
  onApplied: () => Promise<void>;
  onReturnFocus?: () => void;
}) {
  const organization = currentPacks?.find((pack) => pack.type === "organization");
  const directPacks = organization ? [organization] : currentPacks || [];
  const [mode, setMode] = useState<Mode>(
    suggestion ? suggestion.includes(":organization:") ? "organization" : "industries"
      : organization ? "organization" : directPacks.length ? "industries" : "none",
  );
  const [selected, setSelected] = useState(suggestion ? [suggestion] : directPacks.map(packReference));
  const [query, setQuery] = useState("");
  const [working, setWorking] = useState<"review" | "apply" | "chat" | null>(null);
  const [review, setReview] = useState<ScenarioPackReview | null>(null);
  const [error, setError] = useState("");
  const endpoint = `/v1/scenario-pack-targets/${targetId}/review`;

  const choices = new Map<string, PackChoice>();
  for (const pack of packs) {
    if (!pack.publisher || !pack.version) continue;
    const source = pack.pack_source === "bundled" ? "package" : "project";
    const kind = pack.kind === "industry_pack" ? "industry" : "organization";
    const reference = `${source}:${pack.publisher}:${kind}:${pack.name}@${pack.version}`;
    if (pack.hidden && !selected.includes(reference)) continue;
    choices.set(reference, { reference, label: pack.display_name || pack.name, kind, author: pack.publisher_display_name || pack.publisher, version: pack.version, source });
  }
  for (const pack of directPacks) {
    const reference = packReference(pack);
    if (!choices.has(reference)) choices.set(reference, { reference, label: pack.name, kind: pack.type, author: pack.publisher, version: pack.version, source: pack.source });
  }
  const activeKind = mode === "organization" ? "organization" : "industry";
  const references = mode === "none" ? [] : selected.filter((reference) => choices.get(reference)?.kind === activeKind);
  const dependencies = (review?.proposed_packs ?? (organization && references[0] === packReference(organization) ? currentPacks || [] : []))
    .filter((pack) => mode === "organization" && pack.type === "industry").map(packReference);

  function resetReview() {
    setReview(null);
    setError("");
  }

  async function check(apply: boolean) {
    setWorking(apply ? "apply" : "review");
    setError("");
    try {
      const result = await api.request<ScenarioPackReview>(endpoint, "POST", { references, ...(apply ? { revision: review?.revision } : {}) }, 120000);
      if (apply) {
        onClose();
        await onApplied();
      } else {
        setReview(result);
      }
    } catch (failure) {
      if (apply) setReview(null);
      setError(String(failure));
    } finally {
      setWorking(null);
    }
  }

  async function prepare() {
    setWorking("chat");
    setError("");
    try {
      await onPrepare([
        "Please update this editable scenario draft's environment composition to the selection below.",
        references.length ? "Use these exact pack references, including any locked industry dependencies of the organization pack." : "Remove the pack declarations and retain a valid, self-contained inline environment.",
        ...references.map((reference) => `- ${reference}`),
        "Check the current scenario, nested includes, selected pack exports, and merge origins. Preserve unrelated authored content and existing runs. Ask before changing authored overrides or guessing ambiguous mappings. If the selection breaks scenario references, explain the conflicts and propose repairs. Validate with the active configuration and summarize the result.",
      ].join("\n"));
      onClose();
    } catch (failure) {
      setError(String(failure));
    } finally {
      setWorking(null);
    }
  }

  const incomplete = mode !== "none" && !references.length;
  return <Modal title="Choose environment packs" description="Review the effective environment and validation findings before applying a change to the draft." size="lg" className="environment-picker" busy={!!working} onClose={onClose} onCloseAutoFocus={onReturnFocus && ((event) => { event.preventDefault(); onReturnFocus(); })}
    actions={<>
      <button type="button" className="button-quiet" disabled={!!working} onClick={onClose}>Cancel</button>
      <button type="button" className="button-quiet" disabled={!!working || incomplete} onClick={() => void prepare()}>{working === "chat" ? "Preparing…" : "Prepare in chat"}</button>
      {review?.can_apply
        ? <button type="button" className="button-primary" disabled={!!working} onClick={() => void check(true)}>{working === "apply" ? "Applying…" : "Apply to draft"}</button>
        : <button type="button" className="button-primary" disabled={!!working || incomplete} onClick={() => void check(false)}>{working === "review" ? "Reviewing…" : "Review change"}</button>}
    </>}>
    <div className="pack-review">
      {(review || currentPacks) && <section aria-label="Current pack choices">
        <h3>Current selection</h3>
        <References references={review?.current_references ?? directPacks.map(packReference)} />
      </section>}
      <fieldset className="pack-mode" disabled={!!working}>
        <legend>Proposed composition</legend>
        {modes.map(({ value, label }) => <label key={value}>
          <input type="radio" name="composition-mode" checked={mode === value} onChange={() => { setMode(value); resetReview(); }} />{label}
        </label>)}
      </fieldset>
      {mode !== "none" && <>
        <div className="search-box"><Search size={15} /><input aria-label="Search environment packs" placeholder="Search name, publisher, or version…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
        <ul className="pack-choice-list">{Array.from(choices.values()).filter((choice) => choice.kind === activeKind && `${choice.label} ${choice.author} ${choice.reference}`.toLowerCase().includes(query.toLowerCase())).map((choice) => <li key={choice.reference}>
          <label><input type={mode === "organization" ? "radio" : "checkbox"} name={mode === "organization" ? "organization-pack" : undefined} checked={selected.includes(choice.reference)} disabled={!!working} onChange={(event) => {
            setSelected(mode === "organization"
              ? [choice.reference]
              : event.target.checked ? [...selected, choice.reference] : selected.filter((key) => key !== choice.reference));
            resetReview();
          }} />
          <span><strong>{choice.label} <small>{choice.version}</small></strong><small>{choice.author}</small><code>{choice.reference}</code></span></label>
        </li>)}</ul>
        {incomplete && <p className="muted">Select {mode === "organization" ? "an organization" : "at least one industry pack"}.</p>}
      </>}
      {dependencies.length > 0 && <section aria-label="Locked industry dependencies"><h3>Industry dependencies set by the organization</h3><References references={dependencies} /></section>}
      {error && <p role="alert" className="field-error">{error}</p>}
      {review && <section aria-label="Pack change review" aria-live="polite">
        <h3>Review results</h3>
        <References references={references} />
        {!review.changed && <p role="status" className="muted">This composition is already declared.</p>}
        {!!review.current_error && <p className="muted">Current environment could not be resolved. {review.current_error}</p>}
        {review.changed && review.changes?.length ? <><h4>Effective environment changes</h4><ul>{review.changes.map((change) => <li key={change}>{change}</li>)}</ul></> : review.can_apply && !review.current_error && <p className="muted">No effective environment or catalog changes.</p>}
        {!!review.overrides?.length && <><h4>Scenario fields that still take precedence</h4><ul>{review.overrides.map((field) => <li key={field}><code>{field}</code></li>)}</ul></>}
        {!!review.findings?.length && <><h4>Validation findings</h4><ul>{review.findings.map((finding, index) => <li key={index}>{finding}</li>)}</ul></>}
        {!!review.error_count && <p className="field-error">Resolve {review.error_count} validation {review.error_count === 1 ? "error" : "errors"} before applying. Prepare in chat to review repairs.</p>}
      </section>}
    </div>
  </Modal>;
}
