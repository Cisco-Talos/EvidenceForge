import { RecentConversations } from "./RecentConversations";
import { belongsToScenario } from "./scenarioSources";
import { useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowLeft, Boxes, Play, LoaderCircle, Package, Folder, MessageSquareText, ShieldCheck } from "lucide-react";
import type { CatalogItem, CodexHealth, Conversation, NetworkChatContext, StudioApi, StudioEvent, StudioJob, StudioSnapshot, ValidationResult } from "./api";
import { formatBundleSize, formatTime, JobCard, ValidationPanel } from "./components";
import { artifactTitle } from "./artifactNaming";
import type { PropertiesSection } from "./ArtifactProperties";
import { CatalogActionContext, CatalogObjectMenu, projectAssignmentAction } from "./CatalogObjectMenu";
import { ActionShortcut, type ObjectAction } from "./ObjectActions";
import { ChatView } from "./ChatView";
import { ConversationList } from "./ConversationList";
import { HeaderSummary, WorkspaceSection } from "./WorkspaceSection";
import { nextStep, ReadinessPipeline, readinessSteps, type StepId } from "./ReadinessPipeline";
import { StatusPill } from "./StatusPill";
import { ArtifactLifecycle } from "./ArtifactLifecycle";
import { PackWorkflow } from "./PackWorkflow";
import { AssetBrowser } from "./AssetBrowser";
import { EnvironmentView } from "./EnvironmentView";
import { PackEnvironmentView } from "./PackEnvironmentView";
import { NetworkDiagram } from "./NetworkDiagram";
import { useEnvironmentInspection } from "./useEnvironmentInspection";
import { ScenarioRuns } from "./ScenarioRuns";
import { environmentState, generationIsCurrent, scenarioStates } from "./ScenarioStates";
import { currentPrediction, ResourceForecastPanel } from "./ResourceForecastPanel";
import { recentJobs } from "./jobOrder";
import { RequestFeedback, requestTime, type RequestState } from "./RequestFeedback";
import { countLabel, environmentSummary, latestJob, runsSummary, validationSummary } from "./workspaceSummaries";
import { Modal } from "./Modal";

export type WorkspaceTarget = "overview" | "environment" | "conversations" | "validation" | "generation" | "scoring";
export type ValidationActivity = { status: "running"; completedAt?: never; error?: never }
  | { status: "completed"; completedAt: number; error?: never }
  | { status: "failed"; error: string; previousResult?: ValidationResult; completedAt?: never };

export function ScenarioWorkspace({ item, snapshot, conversations, selectedConversation, target, jobs, api, codexHealth, busy, validation: savedValidation, validationActivity, focusJobId, initialDraft, subscribeEvents, onNavigate, onOpenConversation, onCreateConversation, onRenameConversation, onDeleteConversation, onProjectChange, onClone, onExportPack, onDeletePack, onDeleteScenario, onHidden, onViewYaml, onImportPacks, onOpenPack, onGenerate, onValidate, onFix, onPrepare, onAskNetwork, onDraftSubmitted, onChanged, onOpenArtifact, onProperties, onError }: {
  item: CatalogItem; snapshot: StudioSnapshot; conversations: Conversation[]; selectedConversation: string | null;
  target: WorkspaceTarget; jobs: StudioJob[]; api: StudioApi; codexHealth: CodexHealth; busy: boolean;
  validation: Parameters<typeof ValidationPanel>[0]["result"]; focusJobId: string | null; initialDraft?: string;
  validationActivity?: ValidationActivity;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  onNavigate: (target: WorkspaceTarget, jobId?: string | null) => void;
  onOpenConversation: (chat: Conversation) => void; onCreateConversation: () => void;
  onRenameConversation: (chat: Conversation) => void; onDeleteConversation: (chat: Conversation) => void;
  onProjectChange: (id: string | null) => void;
  onClone: () => void; onExportPack: () => void; onDeletePack: () => void; onDeleteScenario: () => void; onHidden: () => void; onViewYaml: () => void;
  onOpenPack?: (pack: CatalogItem) => void;
  onImportPacks: () => void; onGenerate: () => Promise<void>; onValidate: () => void; onFix: () => void;
  onPrepare: (prompt: string) => Promise<void>; onDraftSubmitted: (id: string) => void;
  onAskNetwork?: (context: NetworkChatContext) => Promise<void>;
  onChanged: () => Promise<void>; onOpenArtifact?: (path: string) => Promise<void>; onProperties?: (section?: PropertiesSection) => void; onError: (message: string) => void;
}) {
  const catalog = useContext(CatalogActionContext);
  /** The open section tab; `null` is the Overview of every section. */
  const [tab, setTab] = useState<string | null>(null);
  const [inspectedEnvironment, setInspectedEnvironment] = useState(false);
  const [openedNetwork, setOpenedNetwork] = useState(false);
  const [locallyRefreshingEnvironment, setEnvironmentRefreshing] = useState(false);
  const [localEnvironmentFeedback, setLocalEnvironmentFeedback] = useState<RequestState>({ pending: false });
  const dependencyFeedback = catalog?.environmentFeedback?.(item) || localEnvironmentFeedback;
  const [environmentRefresh, setEnvironmentRefresh] = useState(0);
  const networkOpen = tab === "visualize";
  const inspectEnvironment = item.kind === "scenario" && (tab === "environment" || networkOpen);
  const health = snapshot.dependencies?.[item.id];
  const environmentInspection = useEnvironmentInspection({
    api, item, enabled: inspectEnvironment || inspectedEnvironment,
    dependencyFingerprint: health?.fingerprint,
    refreshVersion: environmentRefresh + (catalog?.environmentRefreshVersion?.(item) || 0),
  });
  const environmentRefreshing = locallyRefreshingEnvironment || catalog?.environmentRefreshing === item.id || environmentInspection.pending;
  useEffect(() => {
    if (inspectEnvironment) setInspectedEnvironment(true);
    if (networkOpen) setOpenedNetwork(true);
  }, [inspectEnvironment, networkOpen]);
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
  const starter = snapshot.starter_drafts?.includes(item.id) || false;
  const prediction = currentPrediction(item, snapshot);
  const forecast = prediction?.result.available ? prediction.result.forecast : null;
  const latestCompleted = latestJob(generations.filter((job) => job.status === "completed" && belongsToScenario(job, item, snapshot) && generationIsCurrent(job, item, snapshot)));
  const latestSize = latestCompleted ? sizes[latestCompleted.id] : null;
  const sizeLabel = starter ? "Forecast · Awaiting authoring" : latestSize != null ? `Latest · ${formatBundleSize(latestSize)}` : forecast ? `Forecast · ~${formatBundleSize(forecast.final_output.expected_bytes)}` : prediction?.result.error ? "Forecast · Unavailable" : "Forecast · Calculating…";
  const latestGeneration = latestJob(generations);
  const latestEvaluation = latestJob(evaluations.filter((job) => job.generation_id === latestGeneration?.id));
  const validation = validationActivity?.status === "failed" ? validationActivity.previousResult : savedValidation;
  const validating = validationActivity?.status === "running";
  const validationFailed = validationActivity?.status === "failed";
  const validationStatus = validating ? { label: "Validation", state: "working" as const, detail: "Checking the current scenario." }
    : validationFailed ? { label: "Validation", state: "error" as const, detail: "The latest validation could not finish." } : states[0];
  const validationInfo = validating ? { headline: "Checking current scenario…", detail: "Previous findings are hidden while validation runs" }
    : validationFailed ? { headline: "Validation could not finish", detail: validation ? "Previous results · retry to check current inputs" : "Retry to check current inputs" }
    : validationSummary(validation, states[0].state === "stale", validationActivity?.completedAt ?? snapshot.validations[item.id]?.completed_at);
  const validationIssues = Array.isArray(validation?.report?.issues) ? validation.report.issues : [];
  const validationDetails = validation && (!validation.report || validationIssues.length > 0 || validation.exit_code !== 0 || validation.report.valid === false);
  const environmentCheckedAt = Math.max(dependencyFeedback.completedAt || 0, environmentInspection.completedAt || 0);
  const environmentError = dependencyFeedback.error || environmentInspection.error;
  const scenarioFacts = `${item.users} ${item.users === 1 ? "user" : "users"} · ${item.systems} ${item.systems === 1 ? "system" : "systems"} · ${item.events} ${item.events === 1 ? "event" : "events"}`;
  const environmentInfo = { ...environmentSummary(health), detail: environmentRefreshing ? "Refreshing environment…"
    : environmentError ? "Refresh could not finish · retry to check current inputs"
    : environmentCheckedAt ? `Checked ${requestTime(environmentCheckedAt)} · ${scenarioFacts}`
    : scenarioFacts };
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
  }, [descriptionExpanded, item.description, chatFocus, networkOpen]);
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
    setTab(section);
    onNavigate("overview", focusJobId);
    requestAnimationFrame(() => list.current?.querySelector(`[data-workspace-section="${section}"]`)?.scrollIntoView?.({ block: "nearest" }));
  }, [target, focusJobId]);
  const toggle = (name: string) => setTab((current) => current === name ? null : name);
  const navigateJob = (job: StudioJob) => onNavigate(job.kind === "evaluation" ? "scoring" : "generation", job.id);
  async function refreshEnvironment() {
    if (environmentRefreshing) return;
    setEnvironmentRefreshing(true);
    setLocalEnvironmentFeedback({ pending: true });
    try {
      await api.request(`/v1/scenarios/${item.id}/dependencies/refresh`, "POST", undefined, 180000);
      await onChanged();
      setEnvironmentRefresh((value) => value + 1);
      setLocalEnvironmentFeedback({ pending: false, completedAt: Date.now() / 1000 });
    } catch (error) { setLocalEnvironmentFeedback({ pending: false, error: String(error) }); }
    finally { setEnvironmentRefreshing(false); }
  }
  const sharedActions = catalog?.actions(item) || [];
  const getAction = (id: string, fallback: ObjectAction): ObjectAction => sharedActions.find((entry) => entry.id === id) || fallback;
  const continueAction = getAction("continue", { id: "continue", label: "Continue", group: "work", disabled: !preferred, reason: "Create a conversation first", description: preferred?.title, run: () => { if (preferred) onOpenConversation(preferred); } });
  const conversationAction = getAction("conversation", { id: "conversation", label: "New conversation", group: "work", run: onCreateConversation });
  const addAssetAction = getAction("add-asset", { id: "add-asset", label: "Add asset…", group: "work", run: () => toggle("assets") });
  const environmentAction = { ...getAction("refresh-environment", { id: "refresh-environment", label: "Refresh environment", group: "work", run: refreshEnvironment }), ...(environmentRefreshing ? { disabled: true, reason: "Environment refresh is in progress" } : {}) };
  const environmentReport = environmentInspection.report;
  const scenarioGraph = environmentReport?.valid && environmentReport.source_sha256 === item.source_sha256
    ? environmentReport.topology : null;
  const validateAction = getAction("validate", { id: "validate", label: "Validate", group: "work", disabled: busy, reason: "Validation is in progress", run: onValidate });
  const fixAction = getAction("fix", { id: "fix", label: "Fix in chat", group: "work", disabled: busy || !validationIssues.length, reason: "Validate to find issues requiring changes", run: onFix });
  const forecastAction = getAction("forecast", { id: "forecast", label: sizeLabel, group: "work", disabled: starter, reason: "Continue authoring before forecasting", run: () => setForecastOpen(true) });
  const generateAction = getAction("generate", { id: "generate", label: "Generate", group: "work", disabled: busy || starter || health?.ready === false, reason: starter ? "Continue authoring before generation" : health?.ready === false ? "Resolve dependency errors first" : "An operation is in progress", run: onGenerate });
  const packExportAction = getAction("export-release", { id: "export-release", label: "Export release…", group: "manage", disabled: !item.version, reason: "Publish a release before exporting", run: onExportPack });
  const localForecastDialog = forecastOpen && <Modal title="Generation forecast" description="Estimates for the current scenario and generation settings." size="lg" className="run-forecast-dialog" dismissOnOutside onClose={() => setForecastOpen(false)} actions={<><button type="button" className="button-quiet" onClick={() => setForecastOpen(false)}>Close</button><button type="button" className="button-primary" onClick={() => { setForecastOpen(false); void onGenerate(); }} disabled={busy || starter || health?.ready === false}>Generate</button></>}><ResourceForecastPanel item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} /></Modal>;
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  useEffect(() => {
    if (!chatFocus) return;
    let canceled = false;
    void api.request<{ sidebar_collapsed?: boolean }>("/v1/chat/preferences").then((value) => {
      if (!canceled) setSidebarCollapsed(value?.sidebar_collapsed || false);
    }).catch(() => undefined);
    return () => { canceled = true; };
  }, [api, snapshot.settings.workspace, chatFocus]);
  function toggleChatSidebar() {
    const collapsed = !sidebarCollapsed; setSidebarCollapsed(collapsed);
    void api.request("/v1/chat/preferences", "PUT", { workspace: snapshot.settings.workspace, sidebar_collapsed: collapsed }).catch((error) => { setSidebarCollapsed(!collapsed); onError(String(error)); });
  }
  // Evaluate the newest completed run of the current revision, as its run row's Evaluate does.
  const evaluationRunning = evaluations.some((job) => job.generation_id === latestCompleted?.id && ["queued", "running", "paused"].includes(job.status));
  const evaluateAction: ObjectAction = {
    id: "evaluate", label: "Evaluate", group: "work", disabled: busy || !latestCompleted || evaluationRunning,
    reason: !latestCompleted ? "Complete a generation of the current revision first" : evaluationRunning ? "This run is already being evaluated" : "An operation is in progress",
    run: async () => {
      if (!latestCompleted) return;
      try { await api.request("/v1/jobs/evaluations", "POST", { generation_id: latestCompleted.id }); await onChanged(); }
      catch (error) { onError(String(error)); }
    },
  };
  const steps = readinessSteps({ starter, conversations: conversations.length, authoring: activeChats > 0, environment: environmentState(health, environmentRefreshing), states: [validationStatus, states[1], states[2]] });
  const openVisualization = () => setTab("visualize");
  const exportBundle = sharedActions.find((entry) => entry.id === "export-bundle");
  const next = item.kind === "scenario" ? nextStep(steps, {
    author: { id: "author", label: "Continue authoring", group: "work", run: () => preferred ? onOpenConversation(preferred) : onCreateConversation() },
    environment: { id: "review-environment", label: "Review environment", group: "work", run: () => setTab("environment") },
    validate: validateAction, fix: fixAction,
    visualize: { id: "visualize", label: "Visualize network", group: "work", run: openVisualization },
    generate: generateAction,
    evaluate: evaluateAction, reevaluate: { ...evaluateAction, id: "reevaluate", label: "Re-evaluate" },
    viewRun: { id: "view-run", label: "Open latest run", group: "work", disabled: !latestGeneration, reason: "No runs yet", run: () => onNavigate(latestEvaluation && latestEvaluation.status !== "completed" ? "scoring" : "generation", (latestEvaluation && latestEvaluation.status !== "completed" ? latestEvaluation : latestGeneration)?.id ?? null) },
    export: exportBundle,
  }, validationIssues.length > 0, openedNetwork) : null;
  function openStep(id: StepId) {
    if (id === "author") { if (preferred) onOpenConversation(preferred); else setTab("conversations"); return; }
    if (id === "visualize") { openVisualization(); return; }
    setTab(id === "environment" ? "environment" : id === "validate" ? "validation" : "runs");
  }
  /** A section header's labeled status, from the same readiness step the strip shows. */
  // The Runs summary already notes unverified inputs, so the pill names the outcome instead.
  const stepPill = (id: StepId, context: string) => {
    const step = steps.find((step) => step.id === id)!;
    return <StatusPill tone={step.tone === "todo" ? "neutral" : step.tone} label={step.status === "Inputs unverified" ? "Generated" : step.status} detail={step.detail} ariaLabel={`${context}: ${step.detail}`} />;
  };
  // The readiness strip owns the promoted action; section headers do not repeat it.
  const promoted = next?.id;
  const findingCount = validationIssues.filter((issue) => ["error", "warning"].includes(String((issue as { severity?: string }).severity || "").toLowerCase())).length;
  const tabs: [string, string, number?, string?][] = item.kind === "scenario"
    // Tabs and cards use the readiness strip's verbs; Environment is a reference section, not a step.
    ? [["overview", "Overview"], ["conversations", "Author", conversations.length], ["environment", "Environment"], ["validation", "Validate", findingCount, validationStatus.state === "error" ? "err" : "warn"], ["visualize", "Visualize"], ["runs", "Generate & Evaluate", runCount]]
    : [["overview", "Overview"], ["conversations", "Author", conversations.length], ["validation", "Validate & Release"], ["assets", "Assets"]];
  if (item.kind === "organization_pack") tabs.splice(3, 0, ["visualize", "Visualize"]);
  const conversationList = <ConversationList conversations={conversations} selectedId={selectedConversation} onOpen={onOpenConversation} onRename={onRenameConversation} onDelete={onDeleteConversation} />;

  return <div className={`scenario-page scenario-workspace ${chatFocus ? "focused" : ""} ${networkOpen ? "network-focused" : ""}`}>
    {localForecastDialog}
    <header className="workspace-heading">
      <div className="workspace-title-row"><button className="artifact-title-button" title="Edit properties" onClick={() => onProperties?.("general")}><h1 title={artifactTitle(item)}>{artifactTitle(item)}</h1></button><span className="scenario-version" title={item.version ? `Version ${item.version}` : "Draft"}>{item.version || "Draft"}</span>
        <span className="workspace-project"><Folder size={15} />{snapshot.projects.find((project) => project.id === item.project_id)?.name || "Ungrouped"}</span>
        <CatalogObjectMenu item={item} fallbackActions={[
          { id: "open", label: "Open", group: "inspect", run: () => onNavigate("overview") },
          { id: "properties", label: "Properties…", group: "locate", run: () => onProperties?.("general") },
          { id: "source", label: "View source", group: "inspect", run: onViewYaml },
          { id: "clone", label: "Duplicate…", group: "manage", run: onClone },
          ...(item.kind !== "scenario" ? [{ id: "export", label: "Export release…", group: "manage" as const, run: onExportPack }] : []),
          projectAssignmentAction(snapshot.projects, onProjectChange),
          { id: "hide", label: item.hidden ? "Show in library" : "Hide from library", group: "organize", run: onHidden },
          ...(item.kind === "scenario" || item.pack_source === "workspace" ? [{ id: "delete", label: item.kind === "scenario" ? "Delete scenario…" : "Delete version…", group: "remove" as const, disabled: busy, reason: "An operation is in progress", run: item.kind === "scenario" ? onDeleteScenario : onDeletePack }] : []),
        ]} />
      </div>
      {!chatFocus && !networkOpen && <div className="workspace-description-area"><p ref={description} className={`workspace-description ${descriptionExpanded ? "expanded" : ""}`}>{item.description || "No description in the source file."}</p>{descriptionOverflow && <button className="workspace-description-more" aria-expanded={descriptionExpanded} onClick={() => setDescriptionExpanded(!descriptionExpanded)}>{descriptionExpanded ? "Show less" : "Show full description"}</button>}</div>}
    </header>
    {!chatFocus && !networkOpen && item.kind === "scenario" && <ReadinessPipeline steps={steps} next={next} hint={next?.id === "generate" ? sizeLabel : (next?.id === "evaluate" || next?.id === "reevaluate") && latestCompleted ? `Latest run · ${formatTime(latestCompleted.started_at || latestCompleted.submitted_at || 0)}` : undefined} onStep={openStep} />}
    {!chatFocus && <div className="workspace-tablist" role="tablist" aria-label="Workspace sections">{tabs.map(([id, label, count, tone]) => <button key={id} type="button" role="tab" aria-label={label} aria-selected={(tab ?? "overview") === id} onClick={() => setTab(id === "overview" ? null : id)}>{label}{count ? <span className={`tab-count ${tone || ""}`} aria-hidden="true">{count}</span> : null}</button>)}</div>}
    {(networkOpen || openedNetwork) && item.kind !== "industry_pack" && <section className="workspace-network" aria-label="Visualize" hidden={!networkOpen || chatFocus}>
      {item.kind === "organization_pack"
        ? <PackEnvironmentView key={item.id} item={item} api={api} subscribeEvents={subscribeEvents} onChanged={onChanged} onAsk={onAskNetwork} />
        : scenarioGraph
          ? <NetworkDiagram key={environmentReport?.compiled_sha256} graph={scenarioGraph} context={artifactTitle(item)} historyKey={item.id}
              exportName={`${artifactTitle(item)} network`} onSaveImage={(image, name) => api.saveImage(image, name)}
              revision={environmentReport?.compiled_sha256 || item.source_sha256} onAsk={onAskNetwork}
              actions={<ActionShortcut action={environmentAction} />} />
          : <div className="diagram-unavailable">
            <ActionShortcut action={environmentAction} />
            <RequestFeedback pending={environmentRefreshing} label="Resolving network diagram…" error={environmentError || (environmentReport && !environmentReport.valid ? environmentReport.error : undefined)} />
            {!environmentRefreshing && !environmentError && environmentReport?.valid && <p className="muted">The network diagram is unavailable for this revision. Refresh the environment to try again.</p>}
          </div>}
    </section>}
    <div className={`workspace-sections ${tab ? "single-section" : "overview-grid"}`} ref={list} hidden={chatFocus || networkOpen}>
      {!tab && <ArtifactLifecycle starter={starter} item={item} api={api} onChanged={onChanged} onOpen={onOpenArtifact} compact onProperties={() => onProperties?.("versions")} />}
      <div data-workspace-section="conversations" hidden={!!tab && tab !== "conversations"}><WorkspaceSection title="Author" icon={<MessageSquareText size={19} />} summary={<HeaderSummary summary={{ headline: [countLabel(conversations.length, "conversation"), activeChats && `${activeChats} working`, attentionChats && `${attentionChats} need input`].filter(Boolean).join(" · "), detail: preferred ? `${preferred.active ? "Continue active" : "Latest"}: ${preferred.title} · ${formatTime(preferred.updated_at)}` : "No conversations yet" }} />} expanded={tab === "conversations"} onToggle={() => toggle("conversations")} actions={<>{preferred && <ActionShortcut action={continueAction} primary={item.kind !== "scenario"} />}<ActionShortcut action={conversationAction} primary={!preferred && item.kind !== "scenario"} /></>} footer={!tab && <RecentConversations conversations={conversations} onOpen={onOpenConversation} />}>
        {conversations.length ? conversationList : undefined}
      </WorkspaceSection></div>
      {item.kind !== "scenario" && <div data-workspace-section="validation" hidden={!!tab && tab !== "validation"}><WorkspaceSection title="Validate & Release" icon={<ShieldCheck size={19} />} summary={<span>Check catalogs and dependencies · export a portable release</span>} expanded={tab === "validation"} onToggle={() => toggle("validation")} actions={<><ActionShortcut action={validateAction} ariaLabel="Validate pack" /><CatalogObjectMenu item={item} label="Validation and release actions" actionIds={["validate", "fix", "publish", "export-release"]} fallbackActions={[validateAction, fixAction, packExportAction]} /></>}><PackWorkflow key={item.id} item={item} api={api} onPrepare={onPrepare} /></WorkspaceSection></div>}
      {item.kind !== "scenario" && <div data-workspace-section="assets" hidden={!!tab && tab !== "assets"}><WorkspaceSection title="Assets" icon={<Package size={19} />} summary={<span>Browse assets · draft edits keep the same draft</span>} expanded={tab === "assets"} onToggle={() => toggle("assets")} actions={<><ActionShortcut action={addAssetAction} /></>}><AssetBrowser key={item.id} item={item} api={api} onChanged={onChanged} embedded /></WorkspaceSection></div>}
      {item.kind === "scenario" && <>
        <div data-workspace-section="environment" aria-busy={environmentRefreshing} hidden={!!tab && tab !== "environment"}><WorkspaceSection title="Environment" keepMounted icon={<Boxes size={19} />} status={stepPill("environment", "Environment")} summary={<HeaderSummary summary={environmentInfo} />} expanded={tab === "environment"} onToggle={() => toggle("environment")} actions={<><ActionShortcut action={environmentAction} />{tab === "environment" && <button type="button" className="button-quiet" onClick={openVisualization}>Open network diagram</button>}</>} footer={environmentError && <div className="workspace-operation-feedback"><RequestFeedback pending={false} label="Refreshing environment…" error={environmentError} /></div>}>
          <EnvironmentView embedded inspection={environmentInspection} dependencyHealth={health} onImportPacks={onImportPacks} onOpenPack={onOpenPack} item={item} packs={snapshot.items.filter((entry) => entry.kind !== "scenario")} api={api} onChanged={onChanged} onPrepare={onPrepare} onError={onError} />
        </WorkspaceSection></div>
        <div data-workspace-section="validation" aria-busy={validating} hidden={!!tab && tab !== "validation"}><WorkspaceSection title="Validate" icon={<ShieldCheck size={19} />} status={stepPill("validate", "Validation")} summary={<HeaderSummary summary={validationInfo} />} expanded={tab === "validation"} onToggle={() => toggle("validation")} actions={<>{!validating && validationIssues.length > 0 && promoted !== fixAction.id && <ActionShortcut action={fixAction} />}{promoted !== validateAction.id && <ActionShortcut action={validateAction} ariaLabel="Validate scenario" />}</>}>
          {validating ? <div className="validation-progress" role="status"><LoaderCircle size={18} aria-hidden="true" />Validating current scenario…</div> : validationFailed ? <><p className="error-text" role="alert">{validationActivity.error}</p>{validation && <><p className="muted">Previous validation results:</p><ValidationPanel result={validation} embedded /></>}</> : validationDetails ? <ValidationPanel result={validation} embedded /> : undefined}
        </WorkspaceSection></div>
        <div data-workspace-section="runs" hidden={!!tab && tab !== "runs"}><WorkspaceSection title="Generate & Evaluate" icon={<Play size={19} />} status={<>{stepPill("generate", "Generation")}{stepPill("evaluate", "Evaluation")}</>} summary={<HeaderSummary summary={runInfo} />} expanded={tab === "runs"} onToggle={() => toggle("runs")} actions={<><ActionShortcut action={forecastAction} className={`run-size-trigger ${forecastAction.label.startsWith("Latest") ? "latest" : "forecast"}`} />{promoted !== generateAction.id && <ActionShortcut action={generateAction} />}</>} footer={tab !== "runs" && active.length > 0 && <div className="workspace-live-runs">{active.map((job) => <JobCard key={job.id} job={job} name={item.name} grouped sizeBytes={sizes[job.id]} idPrefix="live-run" onNavigateRow={() => navigateJob(job)} api={api} onError={onError} onChanged={onChanged} />)}</div>}>
          {runCount ? <ScenarioRuns jobs={jobs} imports={imports} sizes={sizes} item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} focusVersion={runFocusVersion} /> : undefined}
        </WorkspaceSection></div>
      </>}
    </div>
    <div className="workspace-chat-focus" hidden={!chatFocus}>
      <div className="workspace-chat-toolbar"><button className="button-quiet" onClick={() => onNavigate("overview", focusJobId)}><ArrowLeft size={16} /> Back to workspace</button><button className="button-quiet" aria-label={sidebarCollapsed ? "Show conversation list" : "Hide conversation list"} aria-expanded={!sidebarCollapsed} onClick={toggleChatSidebar}><MessageSquareText size={16} />{sidebarCollapsed ? "Show chats" : "Hide chats"}</button><ActionShortcut action={conversationAction} /></div>
      <div className={`conversation-layout ${sidebarCollapsed ? "rail-collapsed" : ""}`}><aside hidden={sidebarCollapsed} className="conversation-rail"><div className="rail-header"><span>CONVERSATIONS</span></div>{conversationList}</aside>
        {selected && <ChatView followupMode={snapshot.settings.chat_followup_mode || "queue"} item={item} conversation={selected} codexHealth={codexHealth} api={api} subscribeEvents={subscribeEvents} initialDraft={initialDraft} onRenamed={onChanged} onDraftSubmitted={onDraftSubmitted} onError={onError} />}
      </div>
    </div>
  </div>;
}
