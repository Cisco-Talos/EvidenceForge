import { useEffect, useState } from "react";
import { Dialog } from "radix-ui";
import type { CatalogItem, PackDeleted, PackDeleteReview, StudioApi } from "./api";

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
      const result = await api.request<PackDeleted>(`/v1/packs/${item.id}/delete`, "POST", { revision: review.revision });
      await onDeleted(result);
    } catch (failure) { setError(String(failure)); setReview(null); }
    finally { setDeleting(false); }
  }
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !deleting) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="modal-backdrop" />
    <Dialog.Content className="close-modal pack-delete-dialog" aria-label="Delete pack version" onPointerDownOutside={(event) => event.preventDefault()} onEscapeKeyDown={(event) => { if (deleting) event.preventDefault(); }}>
      <Dialog.Title>Delete {item.name} {item.version}?</Dialog.Title>
      <Dialog.Description>Remove this exact version and its local conversation associations from Studio. Keep a recovery copy of its files. Codex histories, other versions, exported releases and captured runs remain available.</Dialog.Description>
      {loading && <p role="status">Checking pack files and dependencies…</p>}
      {review && <><p><strong>{review.reference}</strong> · {review.files} files</p>
        {!!review.consumers?.length && <><h4>Used by</h4><ul>{review.consumers.map((consumer) => <li key={consumer}>{consumer}</li>)}</ul><p>Update these references before deleting this version.</p></>}
        {!!review.problems?.length && <ul className="error-text">{review.problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>}
      </>}
      {error && <p className="error-text" role="alert">{error}</p>}
      <div className="close-modal-actions"><button className="button-quiet" disabled={deleting} onClick={onClose}>Cancel</button><button className="button-quiet" disabled={loading || deleting} onClick={() => setRefresh((value) => value + 1)}>Refresh review</button><button className="button-danger" disabled={loading || deleting || !review?.removable} onClick={() => void remove()}>{deleting ? "Deleting…" : "Delete version"}</button></div>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}
