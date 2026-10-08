import { artifactTitle } from "./artifactNaming";
import { useEffect, useState } from "react";
import { Dialog } from "radix-ui";
import { AffectedItems } from "./AffectedItems";
import type { AffectedItem, CatalogItem, PackDeleted, PackDeleteReview, StudioApi } from "./api";

function dependentSummary(items: AffectedItem[]) {
  const scenarios = items.filter((entry) => entry.kind === "scenario").length;
  const packs = items.length - scenarios;
  return [scenarios ? `${scenarios} ${scenarios === 1 ? "scenario" : "scenarios"}` : "", packs ? `${packs} ${packs === 1 ? "pack" : "packs"}` : ""].filter(Boolean).join(" and ");
}

export function DeletePackDialog({ item, api, onClose, onDeleted }: {
  item: CatalogItem; api: StudioApi; onClose: () => void; onDeleted: (result: PackDeleted) => Promise<void>;
}) {
  const [review, setReview] = useState<PackDeleteReview | null>(null);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setReview(null); setError("");
    api.request<PackDeleteReview>(`/v1/packs/${item.id}/deletion`).then((value) => { if (!cancelled) setReview(value); })
      .catch((failure) => { if (!cancelled) setError(String(failure)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, item.id, refresh]);
  async function remove() {
    if (!review?.removable || loading || deleting) return;
    setDeleting(true); setError("");
    try {
      const result = await api.request<PackDeleted>(`/v1/packs/${item.id}/delete`, "POST", { revision: review.revision, accept_dependents: !!review.consumers?.length });
      await onDeleted(result);
    } catch (failure) { setError(String(failure)); setReview(null); }
    finally { setDeleting(false); }
  }
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !deleting) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="modal-backdrop" />
    <Dialog.Content className="close-modal pack-delete-dialog" aria-label="Delete pack version" onPointerDownOutside={(event) => event.preventDefault()} onEscapeKeyDown={(event) => { if (deleting) event.preventDefault(); }}>
      <Dialog.Title>Delete {artifactTitle(item)}{item.version ? ` ${item.version}` : " draft"}?</Dialog.Title>
      <Dialog.Description>Permanently delete this exact pack and its local conversations. This cannot be undone. Export anything you want to keep first. Other versions, Codex histories, exported releases and captured runs remain available.</Dialog.Description>
      {loading && <p role="status">Checking pack files and dependencies…</p>}
      {review && <><p><strong>{review.reference}</strong> · {review.files} files</p>
        {!!review.affected?.length && <><p>{dependentSummary(review.affected)} {review.affected.length === 1 ? "relies" : "rely"} on this pack. Those that need the installed pack may stop validating or generating. Captured runs and self-contained published releases remain usable.</p><AffectedItems key={review.revision} items={review.affected} /></>}
        {!!review.problems?.length && <ul className="error-text">{review.problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>}
      </>}
      {error && <p className="error-text" role="alert">{error}</p>}
      <div className="close-modal-actions"><button className="button-quiet" disabled={deleting} onClick={onClose}>Cancel</button><button className="button-quiet" disabled={loading || deleting} onClick={() => setRefresh((value) => value + 1)}>Refresh review</button><button className="button-danger" disabled={loading || deleting || !review?.removable} onClick={() => void remove()}>{deleting ? "Deleting…" : "Delete version"}</button></div>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}
