import { RemovalButton } from "./ObjectActions";
import { artifactTitle } from "./artifactNaming";
import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import { ChevronRight } from "lucide-react";
import { formatBundleSize } from "./components";
import type { CatalogItem, ScenarioDeleted, ScenarioDeleteReview, StudioApi } from "./api";

export function DeleteScenarioDialog({ item, api, onClose, onDeleted }: {
  item: CatalogItem; api: StudioApi; onClose: () => void; onDeleted: (result: ScenarioDeleted) => Promise<void>;
}) {
  const [includeFiles, setIncludeFiles] = useState(false);
  const [review, setReview] = useState<ScenarioDeleteReview | null>(null);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setReview(null); setError("");
    api.request<ScenarioDeleteReview>(`/v1/scenarios/${item.id}/deletion${includeFiles ? "?include_files=true" : ""}`)
      .then((value) => { if (!cancelled) setReview(value); })
      .catch((failure) => { if (!cancelled) setError(String(failure)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, item.id, refresh, includeFiles]);
  async function remove() {
    if (!review?.removable || loading || deleting) return;
    setDeleting(true); setError("");
    try {
      const result = await api.request<ScenarioDeleted>(`/v1/scenarios/${item.id}/delete`, "POST", { revision: review.revision, include_files: includeFiles });
      await onDeleted(result);
    } catch (failure) { setError(String(failure)); setReview(null); }
    finally { setDeleting(false); }
  }
  return <Modal title={`Delete ${artifactTitle(item)}?`} variant="review" danger busy={deleting} className="pack-delete-dialog" onClose={onClose}
    description="Permanently deletes this scenario and its local conversations. Other drafts and versions, shared packs and Codex histories stay available."
    actions={<><span className="modal-actions-note">Can’t be undone</span><button type="button" className="button-quiet" disabled={deleting} onClick={onClose}>Cancel</button><button type="button" className="button-quiet" disabled={loading || deleting} onClick={() => setRefresh((value) => value + 1)}>Refresh review</button><RemovalButton disabled={loading || deleting || !review?.removable} onClick={() => void remove()}>{deleting ? "Deleting…" : "Delete scenario"}</RemovalButton></>}>
    <label className="delete-all-choice"><input type="checkbox" checked={includeFiles} disabled={deleting} onChange={(event) => setIncludeFiles(event.target.checked)} /> Also delete this scenario’s workspace files, runs and evaluations</label>
    {loading && <p role="status">Checking scenario files and references…</p>}
    {review && <><p><strong>{review.target}</strong> · {review.files} {review.files === 1 ? "file" : "files"} · {formatBundleSize(review.bytes)}</p>
      <p>{includeFiles ? "The selected scenario’s files and associated runs and evaluations will be permanently deleted." : review.whole_artifact ? "This draft or release, including its source material and frozen inputs, will be permanently deleted. Retained runs remain available in Bundles." : "Only the selected scenario YAML will be permanently deleted. Supporting files stay in place; retained runs remain available in Bundles."}</p>
      {includeFiles && <p>{review.run_count || 0} associated runs will be permanently deleted. Imported external bundles remain available on the Bundles page.</p>}
      {!!review.run_paths?.length && <details className="affected-items"><summary><ChevronRight size={13} aria-hidden="true" />Run folders ({review.run_paths.length})</summary><ul>{review.run_paths.map((path) => <li key={path}>{path}</li>)}</ul></details>}
      {!!review.consumers?.length && <><h4>Included by</h4><ul>{review.consumers.map((consumer) => <li key={consumer}>{consumer}</li>)}</ul><p>Update these includes before deleting this scenario.</p></>}
      {!!review.problems?.length && <ul className="error-text">{review.problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>}
    </>}
    {error && <p className="error-text" role="alert">{error}</p>}
  </Modal>;
}
