import { useEffect, useState } from "react";
import { Download, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import type { CatalogItem, PackReview, StudioApi } from "./api";

export function PackWorkflow({ item, api, onPrepare, onExport }: {
  item: CatalogItem; api: StudioApi; onPrepare: (prompt: string) => Promise<void>; onExport: () => void;
}) {
  const [review, setReview] = useState<PackReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  async function prepareRepair() {
    setBusy(true); setError("");
    try { await onPrepare(`Review and repair this pack. First rerun eforge pack validate against the current files. Explain the proposed changes and preserve existing shared or referenced versions by creating a new version before editing. Revalidate the pack and a representative consumer scenario. Current finding: ${review?.error}`); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  useEffect(() => {
    let cancelled = false;
    setBusy(true); setReview(null); setError("");
    api.request<PackReview>(`/v1/packs/${item.id}/review`).then((value) => { if (!cancelled) setReview(value); })
      .catch((failure) => { if (!cancelled) setError(String(failure)); })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [api, item.id, item.source_sha256, refresh]);
  return <div className="pack-workflow">
    <p>Create and revise reusable content in Conversations or Assets. Asset saves create a new exact version; existing scenario selections keep their current version.</p>
    <div className="job-actions"><button className="button-quiet" disabled={busy} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={15} />{busy ? "Checking…" : "Validate pack"}</button><button className="button-primary" disabled={busy || !review?.valid} onClick={onExport}><Download size={15} />Export release…</button></div>
    {error && <p className="error-text" role="alert">{error}</p>}
    {review && (review.valid ? <>
      <p className="state-success"><ShieldCheck size={16} /> Pack and locked dependencies passed validation.</p>
      <p><strong>{review.reference}</strong></p>
      <p className="muted small">Digest: <code>{review.digest}</code></p>
      <h4>Industry dependencies</h4>{review.dependencies?.length ? <ul>{review.dependencies.map((dependency) => <li key={dependency}>{dependency}</li>)}</ul> : <p className="muted">No industry dependencies.</p>}
      <h4>Catalog exports</h4><ul>{Object.entries(review.exports || {}).filter(([, entries]) => entries.length).map(([category, entries]) => <li key={category}>{category.replace(/_catalog$/, "").replace(/_/g, " ")}: {entries.length}</li>)}</ul>
      {item.kind === "organization_pack" && <><h4>Organization model</h4><ul>{Object.entries(review.model_contributions || {}).filter(([, fields]) => fields.length).map(([section, fields]) => <li key={section}>{section.replace(/_/g, " ")}: {fields.join(", ")}</li>)}</ul></>}
      <p className="muted">Export creates a portable .efpack release with its exact dependencies. Import it in another workspace to share it. Validate a scenario using this pack to check the complete environment.</p>
    </> : <><p className="error-text" role="alert"><TriangleAlert size={16} />{review.error || "Pack needs changes before release."}</p><button className="button-quiet" disabled={busy} onClick={() => void prepareRepair()}>Fix in chat</button></>)}
  </div>;
}
