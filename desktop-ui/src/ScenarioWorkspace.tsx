import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowLeft, Copy, Download, Upload, Package, Folder, Gauge, MessageSquareText, MoreHorizontal, Play, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { Dialog, DropdownMenu } from "radix-ui";
import type { CatalogItem, CodexHealth, Conversation, StudioApi, StudioEvent, StudioJob, StudioSnapshot } from "./api";
import { formatTime, ValidationPanel } from "./components";
import { ScenarioTitle } from "./ScenarioTitle";
import { CopyPathButton } from "./CopyPathButton";
import { ChatView } from "./ChatView";
import { ConversationList } from "./ConversationList";
import { HeaderSummary, WorkspaceSection } from "./WorkspaceSection";
import { PackWorkflow } from "./PackWorkflow";
import { AssetBrowser } from "./AssetBrowser";
import { EnvironmentView } from "./EnvironmentView";
import { ScenarioRuns } from "./ScenarioRuns";
import { environmentState, generationIsCurrent, OperationStatus, scenarioStates } from "./ScenarioStates";
import { currentPrediction, ResourceForecastPanel } from "./ResourceForecastPanel";
import { recentJobs } from "./jobOrder";
import { countLabel, environmentSummary, latestJob, latestRunState, runsSummary, validationSummary } from "./workspaceSummaries";

export type WorkspaceTarget = "overview" | "environment" | "conversations" | "validation" | "generation" | "scoring";

export function ScenarioWorkspace({ item, snapshot, conversations, selectedConversation, target, jobs, api, codexHealth, busy, validation, focusJobId, initialDraft, subscribeEvents, onNavigate, onOpenConversation, onCreateConversation, onRenameConversation, onDeleteConversation, onRenameScenario, onProjectChange, onClone, onExportPack, onDeletePack, onHidden, onViewYaml, onImportPacks, onGenerate, onValidate, onFix, onPrepare, onDraftSubmitted, onChanged, onError }: {
  item: CatalogItem; snapshot: StudioSnapshot; conversations: Conversation[]; selectedConversation: string | null;
  target: WorkspaceTarget; jobs: StudioJob[]; api: StudioApi; codexHealth: CodexHealth; busy: boolean;
  validation: Parameters<typeof ValidationPanel>[0]["result"]; focusJobId: string | null; initialDraft?: string;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  onNavigate: (target: WorkspaceTarget, jobId?: string | null) => void;
  onOpenConversation: (chat: Conversation) => void; onCreateConversation: () => void;
  onRenameConversation: (chat: Conversation) => void; onDeleteConversation: (chat: Conversation) => void;
  onRenameScenario: (name: string) => Promise<void>; onProjectChange: (id: string | null) => void;
  onClone: () => void; onExportPack: () => void; onDeletePack: () => void; onHidden: () => void; onViewYaml: () => void;
  onImportPacks: () => void; onGenerate: () => Promise<void>; onValidate: () => void; onFix: () => void;
  onPrepare: (prompt: string) => Promise<void>; onDraftSubmitted: (id: string) => void;
  onChanged: () => Promise<void>; onError: (message: string) => void;
}) {
  const [expanded, setExpanded] = useState<string[]>([]);
  const [environmentRefreshing, setEnvironmentRefreshing] = useState(false);
  const [environmentRefresh, setEnvironmentRefresh] = useState(0);
  const [runFocusVersion, setRunFocusVersion] = useState(0);
  const [forecastOpen, setForecastOpen] = useState(false);
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  const [descriptionExpanded, setDescriptionExpanded] = useState(false);
  const [descriptionOverflow, setDescriptionOverflow] = useState(false);
  const description = useRef<HTMLParagraphElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const chatFocus = target === "conversations";
  const preferred = conversations[0];
  const selected = conversations.find((chat) => chat.id === selectedConversation) || null;
  const generations = recentJobs(jobs.filter((job) => job.kind === "generation"));
  const evaluations = recentJobs(jobs.filter((job) => job.kind === "evaluation"));
  const active = generations.filter((job) => ["running", "queued", "paused"].includes(job.status));
  const states = scenarioStates(item, snapshot);
  const health = snapshot.dependencies?.[item.id];
  const forecast = currentPrediction(item, snapshot)?.result.forecast;
  const latestGeneration = latestJob(generations);
  const latestEvaluation = latestJob(evaluations.filter((job) => job.generation_id === latestGeneration?.id));
  const latestIsCurrent = !latestGeneration || generationIsCurrent(latestGeneration, item, snapshot);
  const validationInfo = validationSummary(validation, states[0].state === "stale", snapshot.validations[item.id]?.completed_at);
  const validationIssues = Array.isArray(validation?.report?.issues) ? validation.report.issues : [];
  const validationDetails = validation && (!validation.report || validationIssues.length > 0 || validation.exit_code !== 0 || validation.report.valid === false);
  const environmentInfo = { ...environmentSummary(health), detail: "Exact pack versions and files · expand to inspect" };
  const activeChats = conversations.filter((chat) => chat.active && !chat.needs_attention).length;
  const attentionChats = conversations.filter((chat) => chat.needs_attention).length;
  // Imported bundles carry scenario names rather than item IDs; only link unambiguous names.
  const imports = snapshot.items.filter((entry) => entry.kind === "scenario" && entry.name === item.name).length === 1
    ? snapshot.imported_bundles.filter((bundle) => bundle.scenario_name === item.name) : [];
  const runCount = generations.length + imports.length;
  const runInfo = runsSummary(generations, imports, evaluations, item, snapshot, sizes, forecast?.final_output.expected_bytes);
  const sizeKey = generations.map((job) => `${job.id}:${job.status}`).join(";");
  useLayoutEffect(() => {
    const paragraph = description.current;
    if (!paragraph || descriptionExpanded) return;
    const measure = () => setDescriptionOverflow(paragraph.scrollHeight > paragraph.clientHeight + 1);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(paragraph);
    return () => observer.disconnect();
  }, [descriptionExpanded, item.description, chatFocus]);
  useEffect(() => {
    if (item.kind !== "scenario" || !generations.length) return;
    let cancelled = false;
    const refreshSizes = () => void api.bundleSizes().then((value) => { if (!cancelled) setSizes(value); }).catch((error) => { if (!cancelled) onError(String(error)); });
    refreshSizes();
    const timer = generations.some((job) => job.status === "running") ? setInterval(refreshSizes, 15000) : null;
    return () => { cancelled = true; if (timer) clearInterval(timer); };
  }, [api, item.id, sizeKey]);
  useEffect(() => {
    if (target === "overview" || target === "conversations") return;
    const section = target === "generation" || target === "scoring" ? "runs" : target;
    if (section === "runs") setRunFocusVersion((value) => value + 1);
    setExpanded((current) => current.includes(section) ? current : [...current, section]);
    onNavigate("overview", focusJobId);
    requestAnimationFrame(() => list.current?.querySelector(`[data-workspace-section="${section}"]`)?.scrollIntoView?.({ block: "nearest" }));
  }, [target, focusJobId]);
  const toggle = (name: string) => setExpanded((current) => current.includes(name) ? current.filter((entry) => entry !== name) : [...current, name]);
  const navigateJob = (job: StudioJob) => onNavigate(job.kind === "evaluation" ? "scoring" : "generation", job.id);
  async function refreshEnvironment() {
    if (environmentRefreshing) return;
    setEnvironmentRefreshing(true);
    try {
      await api.request(`/v1/scenarios/${item.id}/dependencies/refresh`, "POST", undefined, 180000);
      await onChanged();
      setEnvironmentRefresh((value) => value + 1);
    } catch (error) { onError(String(error)); }
    finally { setEnvironmentRefreshing(false); }
  }
  const conversationList = <ConversationList conversations={conversations} selectedId={selectedConversation} onOpen={onOpenConversation} onRename={onRenameConversation} onDelete={onDeleteConversation} />;

  return <div className={`scenario-page scenario-workspace ${chatFocus ? "focused" : ""}`}>
    <header className="workspace-heading">
      <div className="workspace-title-row">{item.kind === "scenario" ? <ScenarioTitle name={item.name} onRename={onRenameScenario} /> : <h1>{item.name}</h1>}
        <label className="workspace-project"><Folder size={15} /><select aria-label={`Project for ${item.name}`} value={item.project_id || ""} onChange={(event) => onProjectChange(event.target.value || null)}><option value="">Ungrouped</option>{snapshot.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
        <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`${item.name} actions`}><MoreHorizontal size={18} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={5}><DropdownMenu.Item onSelect={onClone}><Copy size={14} /> Clone</DropdownMenu.Item><DropdownMenu.Item onSelect={onHidden}>{item.hidden ? "Show in library" : "Hide from library"}</DropdownMenu.Item>{item.kind !== "scenario" && <><DropdownMenu.Item onSelect={onExportPack}>Export release…</DropdownMenu.Item>{item.pack_source === "workspace" && <DropdownMenu.Item disabled={busy} onSelect={onDeletePack}>Delete version…</DropdownMenu.Item>}</>}</DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
      </div>
      {!chatFocus && <div className="workspace-description-area"><p ref={description} className={`workspace-description ${descriptionExpanded ? "expanded" : ""}`}>{item.description || "No description in the source file."}</p>{descriptionOverflow && <button className="workspace-description-more" aria-expanded={descriptionExpanded} onClick={() => setDescriptionExpanded(!descriptionExpanded)}>{descriptionExpanded ? "Show less" : "Show full description"}</button>}</div>}
      <div className="workspace-source"><div className="path-with-copy"><button className="path-value workspace-source-link" aria-label={`View ${item.kind === "scenario" ? "scenario" : "pack"} YAML`} title={`View YAML: ${item.path}`} onClick={onViewYaml}>{item.path}</button><CopyPathButton path={item.path} label={item.kind === "scenario" ? "Copy scenario path" : "Copy pack path"} onError={onError} /></div></div>
      {!chatFocus && <div className="workspace-facts"><span>Version {item.version || "YAML"}</span>{item.kind === "scenario" && <span>{item.users} {item.users === 1 ? "user" : "users"} · {item.systems} {item.systems === 1 ? "system" : "systems"} · {item.events} {item.events === 1 ? "event" : "events"}</span>}<span>Edited {formatTime(item.modified_at)}</span></div>}
    </header>
    <div className="workspace-sections" ref={list} hidden={chatFocus}>
      <WorkspaceSection title="Conversations" icon={<MessageSquareText size={19} />} summary={<HeaderSummary summary={{ headline: [countLabel(conversations.length, "conversation"), activeChats && `${activeChats} working`, attentionChats && `${attentionChats} need input`].filter(Boolean).join(" · "), detail: preferred ? `${preferred.active ? "Continue active" : "Latest"}: ${preferred.title} · ${formatTime(preferred.updated_at)}` : "No conversations yet" }} />} expanded={expanded.includes("conversations")} onToggle={() => toggle("conversations")} actions={<>{preferred && <button className="button-primary" title={`Continue ${preferred.title}${preferred.active ? " (active turn)" : " (most recently updated)"}`} onClick={() => onOpenConversation(preferred)}><MessageSquareText size={15} /> Continue</button>}<button className={preferred ? "button-quiet" : "button-primary"} onClick={onCreateConversation}><Plus size={15} /> New conversation</button></>}>
        {conversations.length ? conversationList : undefined}
      </WorkspaceSection>
      {item.kind !== "scenario" && <WorkspaceSection title="Validation & release" icon={<ShieldCheck size={19} />} summary={<span>Check catalogs and dependencies · export a portable release</span>} expanded={expanded.includes("validation")} onToggle={() => toggle("validation")}><PackWorkflow key={item.id} item={item} api={api} onPrepare={onPrepare} onExport={onExportPack} /></WorkspaceSection>}
      {item.kind !== "scenario" && <WorkspaceSection title="Assets" icon={<Package size={19} />} summary={<span>Browse and edit · changes create a new version</span>} expanded={expanded.includes("assets")} onToggle={() => toggle("assets")} actions={<><button className="button-quiet" onClick={onImportPacks}><Upload size={15} /> Import</button><button className="button-quiet" onClick={onExportPack}><Download size={15} /> Export</button></>}><AssetBrowser key={item.id} item={item} api={api} onChanged={onChanged} /></WorkspaceSection>}
      {item.kind === "scenario" && <>
        <div data-workspace-section="environment"><WorkspaceSection title="Environment" icon={<OperationStatus status={environmentState(health, environmentRefreshing)} focusable={false} />} summary={<HeaderSummary summary={environmentInfo} />} expanded={expanded.includes("environment")} onToggle={() => toggle("environment")} actions={<button className="icon-button" aria-label="Refresh environment" title="Recheck packs, includes, and configuration from disk" disabled={environmentRefreshing} onClick={() => void refreshEnvironment()}><RefreshCw size={16} className={environmentRefreshing ? "spinning" : ""} /></button>}>
          <EnvironmentView embedded refreshVersion={environmentRefresh} dependencyHealth={health} onImportPacks={onImportPacks} item={item} packs={snapshot.items.filter((entry) => entry.kind !== "scenario" && !entry.hidden)} dependencyFingerprint={health?.fingerprint} api={api} onChanged={onChanged} onPrepare={onPrepare} onError={onError} />
        </WorkspaceSection></div>
        <div data-workspace-section="validation"><WorkspaceSection title="Validation" icon={<OperationStatus status={states[0]} focusable={false} />} summary={<HeaderSummary summary={validationInfo} />} expanded={expanded.includes("validation")} onToggle={() => toggle("validation")} actions={<>{validationIssues.length > 0 && <button className="button-quiet" onClick={onFix} disabled={busy} title="Open a new conversation with a prepared request and the current findings"><MessageSquareText size={16} /> Fix in chat</button>}<button className="button-quiet" onClick={onValidate} disabled={busy}><ShieldCheck size={15} /> {busy ? "Working…" : "Validate"}</button></>}>
          {validationDetails ? <ValidationPanel result={validation} embedded /> : undefined}
        </WorkspaceSection></div>
        <div data-workspace-section="runs"><WorkspaceSection title="Runs" icon={<span className="run-outcome-icons"><OperationStatus status={latestRunState("Generation", latestGeneration, latestIsCurrent)} focusable={false} /><OperationStatus status={latestRunState("Evaluation", latestEvaluation, latestIsCurrent)} focusable={false} /></span>} summary={<HeaderSummary summary={runInfo} />} expanded={expanded.includes("runs")} onToggle={() => toggle("runs")} actions={<><Dialog.Root open={forecastOpen} onOpenChange={setForecastOpen}><Dialog.Trigger className="button-quiet"><Gauge size={15} /> Forecast</Dialog.Trigger><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="environment-picker run-forecast-dialog"><Dialog.Title>Generation forecast</Dialog.Title><Dialog.Description>Estimates for the current scenario and generation settings.</Dialog.Description><ResourceForecastPanel item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} /><footer><Dialog.Close className="button-quiet">Close</Dialog.Close><button className="button-primary" onClick={() => { setForecastOpen(false); void onGenerate(); }} disabled={busy || health?.ready === false}><Play size={15} /> Generate</button></footer></Dialog.Content></Dialog.Portal></Dialog.Root><button className="button-quiet" onClick={() => void onGenerate()} disabled={busy || health?.ready === false} title={health?.ready === false ? "Resolve dependency errors first" : "Create a new run using current files and Settings"}><Play size={15} /> Generate</button></>} footer={!expanded.includes("runs") && active.length > 0 && <div className="workspace-live-runs">{active.map((job) => {
            const percent = job.progress?.total_hours ? Math.min(100, Math.round(job.progress.completed_hours / job.progress.total_hours * 100)) : null;
            return <button key={job.id} className="workspace-live-run" onClick={() => navigateJob(job)}><span>Run #{job.id.slice(0, 8)} · {job.status}</span><span className="progress-track" role="progressbar" aria-label={`Run ${job.id} generation progress`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent ?? 0}><span style={{ width: `${percent ?? 0}%` }} /></span><small>{percent === null ? "Preparing" : `${percent}%`}</small></button>;
          })}</div>}>
          {runCount ? <ScenarioRuns jobs={jobs} imports={imports} sizes={sizes} item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} focusVersion={runFocusVersion} /> : undefined}
        </WorkspaceSection></div>
      </>}
    </div>
    <div className="workspace-chat-focus" hidden={!chatFocus}>
      <div className="workspace-chat-toolbar"><button className="button-quiet" onClick={() => onNavigate("overview", focusJobId)}><ArrowLeft size={16} /> Back to workspace</button></div>
      <div className="conversation-layout"><aside className="conversation-rail"><div className="rail-header"><span>CONVERSATIONS</span><button className="icon-button" aria-label="New conversation" title="New conversation" onClick={onCreateConversation}><Plus size={17} /></button></div>{conversationList}</aside>
        {selected && <ChatView item={item} conversation={selected} codexHealth={codexHealth} api={api} subscribeEvents={subscribeEvents} initialDraft={initialDraft} onRenamed={onChanged} onDraftSubmitted={onDraftSubmitted} onError={onError} />}
      </div>
    </div>
  </div>;
}
