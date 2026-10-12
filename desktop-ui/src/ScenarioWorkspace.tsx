import { belongsToScenario } from "./scenarioSources";
import { useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowLeft, Package, Folder, MessageSquareText, ShieldCheck } from "lucide-react";
import { Dialog } from "radix-ui";
import type { CatalogItem, CodexHealth, Conversation, StudioApi, StudioEvent, StudioJob, StudioSnapshot } from "./api";
import { formatBundleSize, formatTime, JobCard, ValidationPanel } from "./components";
import { artifactTitle } from "./artifactNaming";
import type { PropertiesSection } from "./ArtifactProperties";
import { CatalogActionContext, CatalogObjectMenu, projectAssignmentAction } from "./CatalogObjectMenu";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "./ObjectActions";
import { CopyPathButton } from "./CopyPathButton";
import { ChatView } from "./ChatView";
import { ConversationList } from "./ConversationList";
import { HeaderSummary, WorkspaceSection } from "./WorkspaceSection";
import { ArtifactLifecycle } from "./ArtifactLifecycle";
import { PackWorkflow } from "./PackWorkflow";
import { AssetBrowser } from "./AssetBrowser";
import { EnvironmentView } from "./EnvironmentView";
import { ScenarioRuns } from "./ScenarioRuns";
import { environmentState, generationIsCurrent, OperationStatus, scenarioStates } from "./ScenarioStates";
import { currentPrediction, ResourceForecastPanel } from "./ResourceForecastPanel";
import { recentJobs } from "./jobOrder";
import { countLabel, environmentSummary, latestJob, latestRunState, runsSummary, validationSummary } from "./workspaceSummaries";

export type WorkspaceTarget = "overview" | "environment" | "conversations" | "validation" | "generation" | "scoring";

export function ScenarioWorkspace({ item, snapshot, conversations, selectedConversation, target, jobs, api, codexHealth, busy, validation, focusJobId, initialDraft, subscribeEvents, onNavigate, onOpenConversation, onCreateConversation, onRenameConversation, onDeleteConversation, onProjectChange, onClone, onExportPack, onDeletePack, onDeleteScenario, onHidden, onViewYaml, onImportPacks, onOpenPack, onGenerate, onValidate, onFix, onPrepare, onDraftSubmitted, onChanged, onOpenArtifact, onProperties, onError }: {
  item: CatalogItem; snapshot: StudioSnapshot; conversations: Conversation[]; selectedConversation: string | null;
  target: WorkspaceTarget; jobs: StudioJob[]; api: StudioApi; codexHealth: CodexHealth; busy: boolean;
  validation: Parameters<typeof ValidationPanel>[0]["result"]; focusJobId: string | null; initialDraft?: string;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  onNavigate: (target: WorkspaceTarget, jobId?: string | null) => void;
  onOpenConversation: (chat: Conversation) => void; onCreateConversation: () => void;
  onRenameConversation: (chat: Conversation) => void; onDeleteConversation: (chat: Conversation) => void;
  onProjectChange: (id: string | null) => void;
  onClone: () => void; onExportPack: () => void; onDeletePack: () => void; onDeleteScenario: () => void; onHidden: () => void; onViewYaml: () => void;
  onOpenPack?: (pack: CatalogItem) => void;
  onImportPacks: () => void; onGenerate: () => Promise<void>; onValidate: () => void; onFix: () => void;
  onPrepare: (prompt: string) => Promise<void>; onDraftSubmitted: (id: string) => void;
  onChanged: () => Promise<void>; onOpenArtifact?: (path: string) => Promise<void>; onProperties?: (section?: PropertiesSection) => void; onError: (message: string) => void;
}) {
  const catalog = useContext(CatalogActionContext);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [locallyRefreshingEnvironment, setEnvironmentRefreshing] = useState(false);
  const environmentRefreshing = locallyRefreshingEnvironment || catalog?.environmentRefreshing === item.id;
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
  const starter = snapshot.starter_drafts?.includes(item.id) || false;
  const prediction = currentPrediction(item, snapshot);
  const forecast = prediction?.result.available ? prediction.result.forecast : null;
  const latestCompleted = latestJob(generations.filter((job) => job.status === "completed" && belongsToScenario(job, item, snapshot) && generationIsCurrent(job, item, snapshot)));
  const latestSize = latestCompleted ? sizes[latestCompleted.id] : null;
  const sizeLabel = starter ? "Forecast · Awaiting authoring" : latestSize != null ? `Latest · ${formatBundleSize(latestSize)}` : forecast ? `Forecast · ~${formatBundleSize(forecast.final_output.expected_bytes)}` : prediction?.result.error ? "Forecast · Unavailable" : "Forecast · Calculating…";
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
  const sharedActions = catalog?.actions(item) || [];
  const getAction = (id: string, fallback: ObjectAction): ObjectAction => sharedActions.find((entry) => entry.id === id) || fallback;
  const continueAction = getAction("continue", { id: "continue", label: "Continue", group: "work", disabled: !preferred, reason: "Create a conversation first", description: preferred?.title, run: () => { if (preferred) onOpenConversation(preferred); } });
  const conversationAction = getAction("conversation", { id: "conversation", label: "New conversation", group: "work", run: onCreateConversation });
  const environmentAction = getAction("refresh-environment", { id: "refresh-environment", label: "Refresh environment", group: "work", disabled: environmentRefreshing, reason: "Environment refresh is in progress", run: refreshEnvironment });
  const validateAction = getAction("validate", { id: "validate", label: "Validate", group: "work", disabled: busy, reason: "Validation is in progress", run: onValidate });
  const fixAction = getAction("fix", { id: "fix", label: "Fix in chat", group: "work", disabled: busy || !validationIssues.length, reason: "Validate to find issues requiring changes", run: onFix });
  const forecastAction = getAction("forecast", { id: "forecast", label: sizeLabel, group: "work", disabled: starter, reason: "Continue authoring before forecasting", run: () => setForecastOpen(true) });
  const generateAction = getAction("generate", { id: "generate", label: "Generate", group: "work", disabled: busy || starter || health?.ready === false, reason: starter ? "Continue authoring before generation" : health?.ready === false ? "Resolve dependency errors first" : "An operation is in progress", run: onGenerate });
  const packExportAction = getAction("export-release", { id: "export-release", label: "Export release…", group: "reuse", disabled: !item.version, reason: "Publish a release before exporting", run: onExportPack });
  const localForecastDialog = <Dialog.Root open={forecastOpen} onOpenChange={setForecastOpen}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="environment-picker run-forecast-dialog"><Dialog.Title>Generation forecast</Dialog.Title><Dialog.Description>Estimates for the current scenario and generation settings.</Dialog.Description><ResourceForecastPanel item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} /><footer><Dialog.Close className="button-quiet">Close</Dialog.Close><button className="button-primary" onClick={() => { setForecastOpen(false); void onGenerate(); }} disabled={busy || starter || health?.ready === false}>Generate</button></footer></Dialog.Content></Dialog.Portal></Dialog.Root>;
  const conversationList = <ConversationList conversations={conversations} selectedId={selectedConversation} onOpen={onOpenConversation} onRename={onRenameConversation} onDelete={onDeleteConversation} />;

  return <div className={`scenario-page scenario-workspace ${chatFocus ? "focused" : ""}`}>
    {localForecastDialog}
    <header className="workspace-heading">
      <div className="workspace-title-row"><button className="artifact-title-button" title="Edit properties" onClick={() => onProperties?.("general")}><h1 title={artifactTitle(item)}>{artifactTitle(item)}</h1></button>
        <span className="workspace-project"><Folder size={15} />{snapshot.projects.find((project) => project.id === item.project_id)?.name || "Ungrouped"}</span>
        <CatalogObjectMenu item={item} fallbackActions={[
          { id: "open", label: "Open", group: "inspect", run: () => onNavigate("overview") },
          { id: "properties", label: "Properties…", group: "inspect", run: () => onProperties?.("general") },
          { id: "source", label: "View source", group: "inspect", run: onViewYaml },
          { id: "clone", label: "Clone…", group: "reuse", run: onClone },
          ...(item.kind !== "scenario" ? [{ id: "export", label: "Export release…", group: "reuse" as const, run: onExportPack }] : []),
          projectAssignmentAction(snapshot.projects, onProjectChange),
          { id: "hide", label: item.hidden ? "Show in library" : "Hide from library", group: "organize", run: onHidden },
          ...(item.kind === "scenario" || item.pack_source === "workspace" ? [{ id: "delete", label: item.kind === "scenario" ? "Delete scenario" : "Delete version", group: "remove" as const, disabled: busy, reason: "An operation is in progress", run: item.kind === "scenario" ? onDeleteScenario : onDeletePack }] : []),
        ]} />
      </div>
      {!chatFocus && <div className="workspace-description-area"><p ref={description} className={`workspace-description ${descriptionExpanded ? "expanded" : ""}`}>{item.description || "No description in the source file."}</p>{descriptionOverflow && <button className="workspace-description-more" aria-expanded={descriptionExpanded} onClick={() => setDescriptionExpanded(!descriptionExpanded)}>{descriptionExpanded ? "Show less" : "Show full description"}</button>}</div>}
      <div className="workspace-source"><div className="path-with-copy"><button className="path-value workspace-source-link" aria-label={`View ${item.kind === "scenario" ? "scenario" : "pack"} YAML`} title={`View YAML: ${item.path}`} onClick={onViewYaml}>{item.path}</button><CopyPathButton path={item.path} label={item.kind === "scenario" ? "Copy scenario path" : "Copy pack path"} onError={onError} /></div></div>
      {!chatFocus && <div className="workspace-facts"><span>{item.version ? `Version ${item.version}` : "Draft"}</span>{item.kind === "scenario" && <span>{item.users} {item.users === 1 ? "user" : "users"} · {item.systems} {item.systems === 1 ? "system" : "systems"} · {item.events} {item.events === 1 ? "event" : "events"}</span>}<span>Edited {formatTime(item.modified_at)}</span></div>}
    </header>
    <div className="workspace-sections" ref={list} hidden={chatFocus}>
      {starter && <div className="surface" role="status"><p>Ready to author — continue the conversation to build this scenario.</p><button className="button-primary" onClick={() => preferred ? onOpenConversation(preferred) : onCreateConversation()}>Continue authoring</button></div>}
      <ArtifactLifecycle starter={starter} item={item} api={api} onChanged={onChanged} onOpen={onOpenArtifact} compact onProperties={() => onProperties?.("versions")} />
      <WorkspaceSection title="Conversations" icon={<MessageSquareText size={19} />} summary={<HeaderSummary summary={{ headline: [countLabel(conversations.length, "conversation"), activeChats && `${activeChats} working`, attentionChats && `${attentionChats} need input`].filter(Boolean).join(" · "), detail: preferred ? `${preferred.active ? "Continue active" : "Latest"}: ${preferred.title} · ${formatTime(preferred.updated_at)}` : "No conversations yet" }} />} expanded={expanded.includes("conversations")} onToggle={() => toggle("conversations")} actions={<>{preferred && <ActionShortcut action={continueAction} primary />}<ActionShortcut action={conversationAction} primary={!preferred} /><ObjectMenu label="Conversations actions" actions={[continueAction, conversationAction]} /></>}>
        {conversations.length ? conversationList : undefined}
      </WorkspaceSection>
      {item.kind !== "scenario" && <WorkspaceSection title="Validation & release" icon={<ShieldCheck size={19} />} summary={<span>Check catalogs and dependencies · export a portable release</span>} expanded={expanded.includes("validation")} onToggle={() => toggle("validation")}><PackWorkflow key={item.id} item={item} api={api} onPrepare={onPrepare} onExport={onExportPack} /></WorkspaceSection>}
      {item.kind !== "scenario" && <WorkspaceSection title="Assets" icon={<Package size={19} />} summary={<span>Browse assets · draft edits keep the same draft</span>} expanded={expanded.includes("assets")} onToggle={() => toggle("assets")} actions={<><button className="button-quiet" onClick={onImportPacks}>Import packs…</button><ActionShortcut action={packExportAction} /><ObjectMenu label="Assets section actions" actions={[{ id: "import", label: "Import packs…", group: "work", run: onImportPacks }, packExportAction]} /></>}><AssetBrowser key={item.id} item={item} api={api} onChanged={onChanged} /></WorkspaceSection>}
      {item.kind === "scenario" && <>
        <div data-workspace-section="environment"><WorkspaceSection title="Environment" icon={<OperationStatus status={environmentState(health, environmentRefreshing)} focusable={false} />} summary={<HeaderSummary summary={environmentInfo} />} expanded={expanded.includes("environment")} onToggle={() => toggle("environment")} actions={<><ActionShortcut action={environmentAction} /><ObjectMenu label="Environment actions" actions={[environmentAction]} /></>}>
          <EnvironmentView embedded refreshVersion={environmentRefresh + (catalog?.environmentRefreshVersion?.(item) || 0)} dependencyHealth={health} onImportPacks={onImportPacks} onOpenPack={onOpenPack} item={item} packs={snapshot.items.filter((entry) => entry.kind !== "scenario")} dependencyFingerprint={health?.fingerprint} api={api} onChanged={onChanged} onPrepare={onPrepare} onError={onError} />
        </WorkspaceSection></div>
        <div data-workspace-section="validation"><WorkspaceSection title="Validation" icon={<OperationStatus status={states[0]} focusable={false} />} summary={<HeaderSummary summary={validationInfo} />} expanded={expanded.includes("validation")} onToggle={() => toggle("validation")} actions={<>{validationIssues.length > 0 && <ActionShortcut action={fixAction} />}<ActionShortcut action={validateAction} /><ObjectMenu label="Validation actions" actions={[validateAction, fixAction]} /></>}>
          {validationDetails ? <ValidationPanel result={validation} embedded /> : undefined}
        </WorkspaceSection></div>
        <div data-workspace-section="runs"><WorkspaceSection title="Runs" icon={<span className="run-outcome-icons"><OperationStatus status={latestRunState("Generation", latestGeneration, latestIsCurrent)} focusable={false} /><OperationStatus status={latestRunState("Evaluation", latestEvaluation, latestIsCurrent)} focusable={false} /></span>} summary={<HeaderSummary summary={runInfo} />} expanded={expanded.includes("runs")} onToggle={() => toggle("runs")} actions={<><ActionShortcut action={forecastAction} className={`run-size-trigger ${forecastAction.label.startsWith("Latest") ? "latest" : "forecast"}`} /><ActionShortcut action={generateAction} /><ObjectMenu label="Runs actions" actions={[forecastAction, generateAction]} /></>} footer={!expanded.includes("runs") && active.length > 0 && <div className="workspace-live-runs">{active.map((job) => <JobCard key={job.id} job={job} name={item.name} grouped sizeBytes={sizes[job.id]} idPrefix="live-run" onNavigateRow={() => navigateJob(job)} api={api} onError={onError} onChanged={onChanged} />)}</div>}>
          {runCount ? <ScenarioRuns jobs={jobs} imports={imports} sizes={sizes} item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} focusVersion={runFocusVersion} /> : undefined}
        </WorkspaceSection></div>
      </>}
    </div>
    <div className="workspace-chat-focus" hidden={!chatFocus}>
      <div className="workspace-chat-toolbar"><button className="button-quiet" onClick={() => onNavigate("overview", focusJobId)}><ArrowLeft size={16} /> Back to workspace</button></div>
      <div className="conversation-layout"><aside className="conversation-rail"><div className="rail-header"><span>CONVERSATIONS</span><ActionShortcut action={conversationAction} /><ObjectMenu label="Conversation rail actions" actions={[continueAction, conversationAction]} /></div>{conversationList}</aside>
        {selected && <ChatView item={item} conversation={selected} codexHealth={codexHealth} api={api} subscribeEvents={subscribeEvents} initialDraft={initialDraft} onRenamed={onChanged} onDraftSubmitted={onDraftSubmitted} onError={onError} />}
      </div>
    </div>
  </div>;
}
