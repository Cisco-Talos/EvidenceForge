import { ActionShortcut, ObjectMenu, RemovalButton, type ObjectAction } from "./ObjectActions";
import { useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { FolderOpen, TriangleAlert } from "lucide-react";
import type { CatalogItem, Conversation, StudioApi, StudioJob } from "./api";
import { artifactTitle } from "./artifactNaming";
import { CopyPathButton } from "./CopyPathButton";

export function MissingScenarioSource({ item, conversations, jobs, api, onRecovered, onRemoved, onRuns }: {
  item: CatalogItem; conversations: Conversation[]; jobs: StudioJob[]; api: StudioApi;
  onRecovered: (item: CatalogItem) => Promise<void>; onRemoved: () => Promise<void>; onRuns: () => void;
}) {
  const [path, setPath] = useState("");
  const [working, setWorking] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const active = conversations.some((chat) => chat.active) || jobs.some((job) => ["queued", "running", "paused"].includes(job.status));
  async function browse() {
    try {
      const chosen = await invoke<string | null>("choose_import_file", { kind: "scenario" });
      if (chosen) setPath(chosen);
    } catch (failure) { setError(String(failure)); }
  }
  async function recover() {
    setWorking(true); setError(null);
    try {
      const recovered = await api.request<CatalogItem>(`/v1/scenarios/${item.id}/source`, "POST", { path: path.trim() });
      await onRecovered(recovered);
    } catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  async function remove() {
    setWorking(true); setError(null);
    try {
      await api.request(`/v1/scenarios/${item.id}/registration`, "DELETE");
      await onRemoved();
    } catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  const removalAction: ObjectAction = { id: "remove", label: "Remove from library", group: "remove", disabled: working || active, reason: "Finish or stop active work first", description: "Keep files and retained runs", run: () => setConfirmRemove(true) };
  const actions: ObjectAction[] = [
    { id: "recover", label: "Recover missing source…", group: "work", disabled: working || active, reason: "Finish or stop active work first", run: () => document.querySelector<HTMLInputElement>('[aria-label="Scenario YAML path"]')?.focus() },
    { id: "runs", label: "View retained runs", group: "inspect", disabled: !jobs.length, reason: "No retained runs", run: onRuns },
    removalAction,
  ];
  return <section className="missing-source-page" aria-label="Missing scenario source">
    <span className="eyebrow">SOURCE MISSING</span><h1>{artifactTitle(item)}</h1><ObjectMenu label={`Options for ${artifactTitle(item)}`} actions={actions} />
    <p><TriangleAlert size={18} /> Studio remembers this scenario, but its authored YAML file is no longer at the indexed location.</p>
    <div className="path-with-copy"><span className="path-value">{item.path}</span><CopyPathButton path={item.path} label="Copy missing source path" onError={setError} /></div>
    <p>Locate the original file to reconnect its conversations and runs. Studio can automatically reconnect a moved draft when its draft ID has one unambiguous match.</p>
    <form onSubmit={(event) => { event.preventDefault(); void recover(); }}>
      <label className="modal-field">Scenario YAML path<input aria-label="Scenario YAML path" value={path} onChange={(event) => setPath(event.target.value)} disabled={working} /></label>
      <div className="close-modal-actions">{isTauri() && <button type="button" className="button-quiet" disabled={working} onClick={() => void browse()}><FolderOpen size={16} /> Browse…</button>}<button className="button-primary" disabled={working || active || !path.trim()}>Locate source</button></div>
    </form>
    {active && <p className="muted">Finish or stop active chats and jobs before changing this entry.</p>}
    <p className="muted">{conversations.length} conversation{conversations.length === 1 ? "" : "s"} and {jobs.filter((job) => job.kind === "generation").length} runs retained.</p>
    {!!jobs.length && <button className="button-quiet" onClick={onRuns}>View retained runs in Job center</button>}
    {error && <p className="field-error" role="alert">{error}</p>}
    {confirmRemove ? <div className="missing-source-removal"><h2>Remove library entry?</h2><p>This removes the stale registration. Source files, generated bundles, saved conversations and Codex threads are kept. Saved conversations will no longer appear under this library entry.</p><div className="close-modal-actions"><button className="button-quiet" disabled={working} onClick={() => setConfirmRemove(false)}>Cancel</button><RemovalButton disabled={working || active} onClick={() => void remove()}>Remove from library</RemovalButton></div></div> : <ActionShortcut action={removalAction} />}
  </section>;
}
