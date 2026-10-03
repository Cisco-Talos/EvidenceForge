import { useEffect, useRef, useState } from "react";
import { Activity, ArrowUpRight, Check, Folder, Sparkles } from "lucide-react";
import { openPath, openUrl } from "@tauri-apps/plugin-opener";
import { isTauri } from "@tauri-apps/api/core";
import { StudioApi, StudioSettings } from "./api";
import { Help, shortPath } from "./components";
import { CopyPathButton } from "./CopyPathButton";

type Tab = "workspace" | "jobs" | "tools";
interface CodexAccount { type?: string; email?: string }
interface CodexStatus { available: boolean; error?: string; account?: { account?: CodexAccount | null } }

export function SettingsView({ settings, paths, api, onSaved, onError }: {
  settings: StudioSettings;
  paths: { data: string; logs: string };
  api: StudioApi;
  onSaved: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const [tab, setTab] = useState<Tab>("workspace");
  const [draft, setDraft] = useState<StudioSettings>(settings);
  const [savedSettings, setSavedSettings] = useState<StudioSettings>(settings);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState("");
  const lastIncomingSettings = useRef(JSON.stringify(settings));
  const [workspace, setWorkspace] = useState(settings.workspace);
  const [codexStatus, setCodexStatus] = useState<CodexStatus | null>(null);
  const [loginPending, setLoginPending] = useState(false);
  const [installMessage, setInstallMessage] = useState("");
  const [rememberView, setRememberView] = useState(true);
  const [savedRememberView, setSavedRememberView] = useState(true);
  const [libraryReady, setLibraryReady] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(savedSettings) || rememberView !== savedRememberView;
  useEffect(() => {
    let cancelled = false;
    setLibraryReady(false);
    void api.libraryPreferences(settings.workspace).then((preferences) => {
      if (cancelled) return;
      setRememberView(preferences.remember_view !== false);
      setSavedRememberView(preferences.remember_view !== false);
      setLibraryReady(true);
    }).catch((error) => { if (!cancelled) onError(String(error)); });
    return () => { cancelled = true; };
  }, [api, settings.workspace, onError]);
  useEffect(() => {
    const incoming = JSON.stringify(settings);
    if (incoming === lastIncomingSettings.current) return;
    const previous = lastIncomingSettings.current;
    lastIncomingSettings.current = incoming;
    setDraft((current) => JSON.stringify(current) === previous ? settings : current);
    setSavedSettings(settings);
    setWorkspace(settings.workspace);
  }, [settings]);
  useEffect(() => { if (dirty) setSaveStatus(""); }, [dirty]);
  useEffect(() => {
    if (tab === "tools") void api.request<CodexStatus>("/v1/codex/status").then(setCodexStatus).catch((error) => onError(String(error)));
  }, [api, tab, onError]);
  useEffect(() => {
    if (!loginPending || tab !== "tools") return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const deadline = Date.now() + 120_000;
    async function poll() {
      try {
        const result = await api.request<CodexStatus>("/v1/codex/status");
        if (cancelled) return;
        setCodexStatus(result);
        if (result.account?.account) {
          setLoginPending(false);
          return;
        }
      } catch (error) {
        if (!cancelled) onError(String(error));
      }
      if (!cancelled && Date.now() < deadline) timer = setTimeout(() => void poll(), 2500);
      else if (!cancelled) setLoginPending(false);
    }
    timer = setTimeout(() => void poll(), 2500);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [api, loginPending, onError, tab]);

  const updateQuit = (change: Partial<StudioSettings["quit"]>) =>
    setDraft({ ...draft, quit: { ...draft.quit, ...change } });

  async function save() {
    if (!dirty || saving) return;
    setSaving(true);
    try {
      const saved = await api.request<StudioSettings>("/v1/settings", "PUT", {
        ...draft,
        max_concurrent_generations: Math.min(16, Math.max(1, draft.max_concurrent_generations)),
      });
      if (rememberView !== savedRememberView) {
        await api.request(`/v1/library/preferences?workspace=${encodeURIComponent(settings.workspace)}`, "PUT", { remember_view: rememberView });
        setSavedRememberView(rememberView);
      }
      setSavedSettings(saved);
      setDraft(saved);
      await onSaved();
      setSaveStatus("Settings saved");
    }
    catch (error) { onError(String(error)); }
    finally { setSaving(false); }
  }

  async function selectWorkspace() {
    try { await api.request("/v1/workspaces/select", "POST", { path: workspace }); await onSaved(); }
    catch (error) { onError(String(error)); }
  }

  async function openLocalFolder(path: string) {
    if (!isTauri()) {
      onError("Folder opening is available in the native app. Use the adjacent copy icon for this path.");
      return;
    }
    try { await openPath(path); }
    catch (error) { onError(String(error)); }
  }

  async function accountAction() {
    try {
      if (codexStatus?.account?.account) {
        await api.request("/v1/codex/account/logout", "POST");
        setLoginPending(false);
      } else {
        const response = await api.request<{ authUrl?: string }>("/v1/codex/account/login", "POST");
        if (response.authUrl) {
          if (isTauri()) await openUrl(response.authUrl);
          else window.open(response.authUrl, "_blank", "noopener,noreferrer");
          setLoginPending(true);
        }
      }
      setCodexStatus(await api.request<CodexStatus>("/v1/codex/status"));
    } catch (error) { onError(String(error)); }
  }

  async function installSkills() {
    try {
      const result = await api.request<{ installed: Record<string, number>; failures: Record<string, string> }>(
        "/v1/codex/skills/install", "POST",
        { scope: draft.skill_install_scope, agent: draft.skill_install_agent },
      );
      const count = Object.values(result.installed).reduce((total, next) => total + next, 0);
      const failures = Object.entries(result.failures);
      setInstallMessage(failures.length ? `Installed ${count} files; ${failures.map(([name, detail]) => `${name}: ${detail}`).join("; ")}` : `Installed ${count} skill files`);
      setCodexStatus(await api.request<CodexStatus>("/v1/codex/status"));
    } catch (error) { onError(String(error)); }
  }

  const account = codexStatus?.account?.account;
  const accountIdentity = !codexStatus ? "Checking Codex…"
    : !codexStatus.available ? (codexStatus.error || "Codex unavailable")
    : !account ? (loginPending ? "Waiting for sign-in…" : "Signed out")
    : account.type === "chatgpt" ? (account.email || "ChatGPT account")
    : account.type === "apiKey" ? "API key authentication"
    : account.type === "amazonBedrock" ? "Amazon Bedrock"
    : "Signed in";

  return <div className="settings-layout">
    <div className="settings-nav">
      <button className={tab === "workspace" ? "active" : ""} onClick={() => setTab("workspace")}><Folder size={16} /> Workspace</button>
      <button className={tab === "jobs" ? "active" : ""} onClick={() => setTab("jobs")}><Activity size={16} /> Jobs</button>
      <button className={tab === "tools" ? "active" : ""} onClick={() => setTab("tools")}><Sparkles size={16} /> Authoring & tools</button>
    </div>
    <div className="settings-main">
      {tab === "workspace" && <>
        <div className="section-heading"><div><h2>Workspace</h2><p>Where authored scenarios, packs, and generated runs live.</p></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Remember library views</strong><Help text="Restore the last project, search, filters, and sorting for scenarios and packs in this workspace. Turning this off opens each library with its default view." /></div><input className="visible-check" type="checkbox" aria-label="Remember library views" disabled={!libraryReady} checked={rememberView} onChange={(event) => setRememberView(event.target.checked)} /></div>
        <div className="setting-row"><div className="setting-copy"><strong>Search matches per item</strong><Help text="Show this many matching fields or source lines (five by default). Names and descriptions rank first, then YAML values, keys, and comments. Substring matching is unchanged; extra matches are counted." /></div><input className="setting-number" type="number" min={1} max={50} aria-label="Search matches per item" value={draft.search_match_limit ?? 5} onChange={(event) => setDraft({ ...draft, search_match_limit: Number(event.target.value) })} onBlur={() => setDraft((current) => ({ ...current, search_match_limit: Math.min(50, Math.max(1, current.search_match_limit || 5)) }))} /></div>
        <div className="setting-row"><div className="setting-copy"><strong>Current workspace</strong><Help text="The app opens this workspace on launch, independent of the terminal's current directory." /></div><div className="setting-control path-control"><input value={workspace} onChange={(event) => setWorkspace(event.target.value)} aria-label="Current workspace" /><CopyPathButton path={workspace} label="Copy workspace path" onError={onError} /><button className="icon-button" title="Open workspace folder" aria-label="Open workspace folder" onClick={() => void openLocalFolder(settings.workspace)}><ArrowUpRight size={16} /></button><button onClick={() => void selectWorkspace()}>Switch</button></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>App data</strong><Help text="Private scenario organization, conversations, job history, and settings. Authored YAML and bundles stay in your workspace." /></div><div className="setting-control"><span className="path-label" title={paths.data}>{shortPath(paths.data)}</span><CopyPathButton path={paths.data} label="Copy app data path" onError={onError} /><button className="icon-button" title="Open app data folder" aria-label="Open app data folder" onClick={() => void openLocalFolder(paths.data)}><ArrowUpRight size={16} /></button></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Service logs</strong><Help text="Diagnostic logs for the local background service." /></div><div className="setting-control"><span className="path-label" title={paths.logs}>{shortPath(paths.logs)}</span><CopyPathButton path={paths.logs} label="Copy logs path" onError={onError} /><button className="icon-button" title="Open logs folder" aria-label="Open logs folder" onClick={() => void openLocalFolder(paths.logs)}><ArrowUpRight size={16} /></button></div></div>
      </>}
      {tab === "jobs" && <>
        <div className="section-heading"><div><h2>Job capacity</h2><p>Control how many resource-heavy runs start at once.</p></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Concurrent generations</strong><Help text="The local controller starts at most this many EvidenceForge generations at once. Additional runs remain queued; evaluations are not counted." /></div><input className="setting-number" type="number" min={1} max={16} aria-label="Concurrent generations" value={draft.max_concurrent_generations || ""} onChange={(event) => setDraft({ ...draft, max_concurrent_generations: Number(event.target.value) })} onBlur={() => setDraft((current) => ({ ...current, max_concurrent_generations: Math.min(16, Math.max(1, current.max_concurrent_generations)) }))} /></div>
        <div className="setting-row"><div className="setting-copy"><strong>Hours between checkpoints</strong><Help text="Save a resumable checkpoint after this many simulated hours. The eforge default is 24. Zero disables checkpoints and cannot be used with Checkpoint and pause on quit. Changes apply to new runs." /></div><input className="setting-number" type="number" min={0} aria-label="Hours between checkpoints" value={draft.checkpoint_hours} onChange={(event) => setDraft({ ...draft, checkpoint_hours: Number(event.target.value) })} /></div>
        <div className="section-heading"><div><h2>When I quit</h2><p>These choices apply the next time you close the window.</p></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Generation and evaluation jobs</strong><Help text="Only jobs started by this app are affected. Terminal eforge processes are never controlled." /></div><select value={draft.quit.action} onChange={(event) => updateQuit({ action: event.target.value as StudioSettings["quit"]["action"] })}><option value="continue">Continue in background</option><option value="pause">Checkpoint and pause</option><option value="kill">Kill app-owned jobs</option></select></div>
        {draft.quit.action === "continue" && <>
          <div className="setting-row"><div className="setting-copy"><strong>Start queued generations</strong><Help text="Continue starting queued generations after the window closes." /></div><input className="visible-check" type="checkbox" checked={draft.quit.continue_queued_generations} onChange={(event) => updateQuit({ continue_queued_generations: event.target.checked })} /></div>
          <div className="setting-row"><div className="setting-copy"><strong>Evaluations</strong><Help text="Choose whether evaluations continue, wait for reopening, or require manual restart." /></div><select value={draft.quit.continue_evaluations} onChange={(event) => updateQuit({ continue_evaluations: event.target.value as StudioSettings["quit"]["continue_evaluations"] })}><option value="continue">Continue</option><option value="hold">Hold and restart on reopen</option><option value="manual">Stop; restart manually</option></select></div>
        </>}
        {draft.quit.action === "pause" && <>
          <div className="setting-row"><div className="setting-copy"><strong>Close timing</strong><Help text="Close after durable handoff, or wait for active generations to checkpoint and stop." /></div><select value={draft.quit.pause_close_timing} onChange={(event) => updateQuit({ pause_close_timing: event.target.value as StudioSettings["quit"]["pause_close_timing"] })}><option value="handoff">Close after handoff</option><option value="wait">Wait for checkpoints</option></select></div>
          <div className="setting-row"><div className="setting-copy"><strong>Active evaluations</strong><Help text="Let evaluations finish, or stop and rerun them when work resumes." /></div><select value={draft.quit.pause_evaluations} onChange={(event) => updateQuit({ pause_evaluations: event.target.value as StudioSettings["quit"]["pause_evaluations"] })}><option value="finish">Let them finish</option><option value="restart">Stop and rerun</option></select></div>
        </>}
        {draft.quit.action === "kill" && <div className="setting-row"><div className="setting-copy"><strong>Incomplete bundles</strong><Help text="Deletion applies only to verified incomplete bundles created by this app, with confirmation at close." /></div><select value={draft.quit.kill_incomplete_bundles} onChange={(event) => updateQuit({ kill_incomplete_bundles: event.target.value as StudioSettings["quit"]["kill_incomplete_bundles"] })}><option value="preserve">Preserve files</option><option value="delete">Delete after confirmation</option></select></div>}
        <div className="setting-row"><div className="setting-copy"><strong>Authoring turns</strong><Help text="Stop active Codex turns when closing, or let them finish in the local service. Turns needing approval wait for reopening." /></div><select value={draft.quit.authoring_turns} onChange={(event) => updateQuit({ authoring_turns: event.target.value as StudioSettings["quit"]["authoring_turns"] })}><option value="stop">Stop active turns</option><option value="finish">Finish in background</option></select></div>
      </>}
      {tab === "tools" && <>
        <div className="section-heading"><div><h2>Authoring & tools</h2><p>Codex handles interactive work. eforge handles deterministic operations.</p></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Codex account</strong><Help text="The identity is read from Codex. Credentials remain in Codex's own storage." /></div><div className="setting-control"><span className="path-label" role="status">{accountIdentity}</span><button className="button-quiet" disabled={!codexStatus?.available || loginPending} onClick={() => void accountAction()}>{account ? "Sign out" : "Sign in"}</button></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Skill install location</strong><Help text="Global installs are available across workspaces; workspace installs stay with this project." /></div><select value={draft.skill_install_scope} onChange={(event) => setDraft({ ...draft, skill_install_scope: event.target.value as StudioSettings["skill_install_scope"] })}><option value="global">Global</option><option value="workspace">This workspace</option></select></div>
        <div className="setting-row"><div className="setting-copy"><strong>Install for</strong><Help text="Choose which agent's skill directory receives EvidenceForge instructions." /></div><select value={draft.skill_install_agent} onChange={(event) => setDraft({ ...draft, skill_install_agent: event.target.value as StudioSettings["skill_install_agent"] })}><option value="all">All agents</option><option value="chatgpt">Codex</option><option value="claude">Claude Code</option></select></div>
        <div className="setting-row"><div className="setting-copy"><strong>EvidenceForge skills</strong><Help text="Copy the repository's current skill files to the selected agent directories. Existing versions are updated." /></div><div className="setting-control"><span className="path-label">{installMessage || `${draft.skill_install_scope} · ${draft.skill_install_agent}`}</span><button className="button-quiet" onClick={() => void installSkills()}>Install or update</button></div></div>
        <div className="setting-row"><div className="setting-copy"><strong>Codex executable</strong><Help text="Automatic uses Codex on PATH, then common CLI install locations on macOS, then Codex.app. Available models come from the selected Codex version. After changing this path, save and reconnect Codex using the status dot in the header." /></div><input value={draft.codex_path || ""} onChange={(event) => setDraft({ ...draft, codex_path: event.target.value || null })} placeholder="Automatic" /></div>
        <div className="setting-row"><div className="setting-copy"><strong>eforge executable</strong><Help text="Leave empty to use this Python environment's eforge CLI." /></div><input value={draft.eforge_path || ""} onChange={(event) => setDraft({ ...draft, eforge_path: event.target.value || null })} placeholder="Automatic" /></div>
      </>}
      <div className="settings-footer"><span role="status" className="settings-save-status">{saveStatus}</span><button className="button-primary" disabled={!dirty || saving} onClick={() => void save()}><Check size={16} /> {saving ? "Saving…" : "Save settings"}</button></div>
    </div>
  </div>;
}
