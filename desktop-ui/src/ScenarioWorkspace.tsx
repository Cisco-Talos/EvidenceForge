import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowLeft, ClipboardCheck, Copy, Download, FileCode2, Folder, FolderOpen, Layers3, MessageSquareText, MoreHorizontal, Play, Plus, ShieldCheck } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import { isTauri } from "@tauri-apps/api/core";
import type { CatalogItem, CodexHealth, Conversation, StudioApi, StudioEvent, StudioJob, StudioSnapshot } from "./api";
import { formatBundleSize, formatTime, JobCard, ValidationPanel } from "./components";
import { ScenarioTitle } from "./ScenarioTitle";
import { CopyPathButton } from "./CopyPathButton";
import { ChatView } from "./ChatView";
import { ConversationList } from "./ConversationList";
import { WorkspaceSection } from "./WorkspaceSection";
import { EnvironmentView } from "./EnvironmentView";
import { DependencyPanel } from "./DependencyPanel";
import { ScenarioOperations } from "./ScenarioOperations";
import { generationIsCurrent, OperationStatus, scenarioStates } from "./ScenarioStates";
import { currentPrediction } from "./ResourceForecastPanel";
import { ImportedBundleRow } from "./BundleLibrary";
import { chronologicalJobs } from "./jobOrder";

export type WorkspaceTarget = "overview" | "environment" | "conversations" | "validation" | "generation" | "scoring";

export function ScenarioWorkspace({ item, snapshot, conversations, selectedConversation, target, jobs, api, codexHealth, busy, validation, focusJobId, initialDraft, subscribeEvents, onNavigate, onOpenConversation, onCreateConversation, onRenameConversation, onDeleteConversation, onRenameScenario, onProjectChange, onClone, onHidden, onViewYaml, onExport, onImportPacks, onGenerate, onValidate, onFix, onPrepare, onDraftSubmitted, onChanged, onError }: {
  item: CatalogItem; snapshot: StudioSnapshot; conversations: Conversation[]; selectedConversation: string | null;
  target: WorkspaceTarget; jobs: StudioJob[]; api: StudioApi; codexHealth: CodexHealth; busy: boolean;
  validation: Parameters<typeof ValidationPanel>[0]["result"]; focusJobId: string | null; initialDraft?: string;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  onNavigate: (target: WorkspaceTarget, jobId?: string | null) => void;
  onOpenConversation: (chat: Conversation) => void; onCreateConversation: () => void;
  onRenameConversation: (chat: Conversation) => void; onDeleteConversation: (chat: Conversation) => void;
  onRenameScenario: (name: string) => Promise<void>; onProjectChange: (id: string | null) => void;
  onClone: () => void; onHidden: () => void; onViewYaml: () => void; onExport: () => void;
  onImportPacks: () => void; onGenerate: () => Promise<void>; onValidate: () => void; onFix: () => void;
  onPrepare: (prompt: string) => Promise<void>; onDraftSubmitted: (id: string) => void;
  onChanged: () => Promise<void>; onError: (message: string) => void;
}) {
  const [expanded, setExpanded] = useState<string[]>([]);
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  const [descriptionExpanded, setDescriptionExpanded] = useState(false);
  const [descriptionOverflow, setDescriptionOverflow] = useState(false);
  const description = useRef<HTMLParagraphElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const chatFocus = target === "conversations";
  const preferred = conversations[0];
  const selected = conversations.find((chat) => chat.id === selectedConversation) || null;
  const generations = chronologicalJobs(jobs.filter((job) => job.kind === "generation"));
  const evaluations = chronologicalJobs(jobs.filter((job) => job.kind === "evaluation"));
  const completed = generations.filter((job) => job.status === "completed");
  const active = generations.filter((job) => ["running", "queued", "paused"].includes(job.status));
  const states = scenarioStates(item, snapshot);
  const health = snapshot.dependencies?.[item.id];
  const forecast = currentPrediction(item, snapshot)?.result.forecast;
  const latestScore = [...evaluations].reverse().find((job) => job.scorecard);
  const freshGeneration = [...completed].reverse().find((job) => generationIsCurrent(job, item, snapshot));
  const actualSize = freshGeneration ? sizes[freshGeneration.id] : null;
  // Imported bundles carry scenario names rather than item IDs; only link unambiguous names.
  const imports = snapshot.items.filter((entry) => entry.kind === "scenario" && entry.name === item.name).length === 1
    ? snapshot.imported_bundles.filter((bundle) => bundle.scenario_name === item.name) : [];
  const bundleCount = generations.length + imports.length;
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
    setExpanded((current) => current.includes(target) ? current : [...current, target]);
    onNavigate("overview", focusJobId);
    requestAnimationFrame(() => list.current?.querySelector(`[data-workspace-section="${target}"]`)?.scrollIntoView?.({ block: "nearest" }));
  }, [target, focusJobId]);
  const toggle = (name: string) => setExpanded((current) => current.includes(name) ? current.filter((entry) => entry !== name) : [...current, name]);
  const navigateJob = (job: StudioJob) => onNavigate(job.kind === "evaluation" ? "scoring" : "generation", job.id);
  const operationDetails = (mode: "generation" | "scoring") => <ScenarioOperations embedded mode={mode} snapshot={snapshot} item={item} jobs={jobs} api={api} onGenerate={onGenerate} generating={busy} dependenciesReady={health?.ready !== false} onError={onError} onChanged={onChanged} focusJobId={focusJobId} onNavigateJob={navigateJob} />;
  const conversationList = <ConversationList conversations={conversations} selectedId={selectedConversation} onOpen={onOpenConversation} onRename={onRenameConversation} onDelete={onDeleteConversation} />;

  return <div className={`scenario-page scenario-workspace ${chatFocus ? "focused" : ""}`}>
    <header className="workspace-heading">
      <div className="workspace-title-row">{item.kind === "scenario" ? <ScenarioTitle name={item.name} onRename={onRenameScenario} /> : <h1>{item.name}</h1>}
        <label className="workspace-project"><Folder size={15} /><select aria-label={`Project for ${item.name}`} value={item.project_id || ""} onChange={(event) => onProjectChange(event.target.value || null)}><option value="">Ungrouped</option>{snapshot.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
        <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`${item.name} actions`}><MoreHorizontal size={18} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={5}><DropdownMenu.Item onSelect={onClone}><Copy size={14} /> Clone</DropdownMenu.Item><DropdownMenu.Item onSelect={onHidden}>{item.hidden ? "Show in library" : "Hide from library"}</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
      </div>
      {!chatFocus && <div className="workspace-description-area"><p ref={description} className={`workspace-description ${descriptionExpanded ? "expanded" : ""}`}>{item.description || "No description in the source file."}</p>{descriptionOverflow && <button className="workspace-description-more" aria-expanded={descriptionExpanded} onClick={() => setDescriptionExpanded(!descriptionExpanded)}>{descriptionExpanded ? "Show less" : "Show full description"}</button>}</div>}
      <div className="workspace-source"><div className="path-with-copy"><span className="path-value" title={item.path}>{item.path}</span><CopyPathButton path={item.path} label={item.kind === "scenario" ? "Copy scenario path" : "Copy pack path"} onError={onError} /></div><button className="button-quiet" onClick={onViewYaml}><FileCode2 size={14} /> View YAML</button></div>
      {!chatFocus && <div className="workspace-facts"><span>Version {item.version || "YAML"}</span>{item.kind === "scenario" && <span>{item.users} {item.users === 1 ? "user" : "users"} · {item.systems} {item.systems === 1 ? "system" : "systems"} · {item.events} {item.events === 1 ? "event" : "events"}</span>}<span>Edited {formatTime(item.modified_at)}</span></div>}
    </header>
    <div className="workspace-sections" ref={list} hidden={chatFocus}>
      <WorkspaceSection title="Conversations" icon={<MessageSquareText size={19} />} summary={preferred ? `${conversations.length} · ${preferred.active ? preferred.needs_attention ? "Needs input" : "Working" : "Latest"}: ${preferred.title}` : "Start authoring in a new conversation"} expanded={expanded.includes("conversations")} onToggle={() => toggle("conversations")} actions={<>{preferred && <button className="button-primary" title={`Continue ${preferred.title}${preferred.active ? " (active turn)" : " (most recently updated)"}`} onClick={() => onOpenConversation(preferred)}><MessageSquareText size={15} /> Continue</button>}<button className={preferred ? "button-quiet" : "button-primary"} onClick={onCreateConversation}><Plus size={15} /> New conversation</button></>}>
        {conversations.length ? conversationList : undefined}
      </WorkspaceSection>
      {item.kind === "scenario" && <>
        <div data-workspace-section="environment"><WorkspaceSection title="Environment" icon={<Layers3 size={19} />} summary={health?.ready === false ? "Dependency errors · repair before generating" : "Packs, configuration layers, and source declarations"} expanded={expanded.includes("environment")} onToggle={() => toggle("environment")}>
          <DependencyPanel itemId={item.id} health={health} api={api} onChanged={onChanged} onImport={onImportPacks} />
          <EnvironmentView embedded item={item} packs={snapshot.items.filter((entry) => entry.kind !== "scenario" && !entry.hidden)} dependencyFingerprint={health?.fingerprint} api={api} onPrepare={onPrepare} onError={onError} />
        </WorkspaceSection></div>
        <div data-workspace-section="validation"><WorkspaceSection title="Validation" icon={<OperationStatus status={states[0]} focusable={false} />} summary={states[0].detail} expanded={expanded.includes("validation")} onToggle={() => toggle("validation")} actions={<button className="button-quiet" onClick={onValidate} disabled={busy}><ShieldCheck size={15} /> {busy ? "Working…" : "Validate"}</button>}>
          {validation ? <ValidationPanel result={validation} onFix={onFix} fixing={busy} /> : undefined}
        </WorkspaceSection></div>
        <div data-workspace-section="generation"><WorkspaceSection title="Generation" icon={<OperationStatus status={states[1]} focusable={false} />} summary={<>{generations.length} {generations.length === 1 ? "run" : "runs"}{actualSize != null ? <> · Generated data {formatBundleSize(actualSize)}</> : forecast && <> · Estimated data {formatBundleSize(forecast.final_output.expected_bytes)}</>}</>} expanded={expanded.includes("generation")} onToggle={() => toggle("generation")} actions={<button className="button-quiet" onClick={() => void onGenerate()} disabled={busy || health?.ready === false} title={health?.ready === false ? "Resolve dependency errors first" : "Create a new run using current files and Settings"}><Play size={15} /> Generate</button>} footer={!expanded.includes("generation") && active.length > 0 && <div className="workspace-live-runs">{active.map((job) => {
            const percent = job.progress?.total_hours ? Math.min(100, Math.round(job.progress.completed_hours / job.progress.total_hours * 100)) : null;
            return <button key={job.id} className="workspace-live-run" onClick={() => navigateJob(job)}><span>Run #{job.id.slice(0, 8)} · {job.status}</span><span className="progress-track" role="progressbar" aria-label={`Run ${job.id} generation progress`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent ?? 0}><span style={{ width: `${percent ?? 0}%` }} /></span><small>{percent === null ? "Preparing" : `${percent}%`}</small></button>;
          })}</div>}>
          {operationDetails("generation")}
        </WorkspaceSection></div>
        <div data-workspace-section="scoring"><WorkspaceSection title="Scoring" icon={<OperationStatus status={states[2]} focusable={false} />} summary={latestScore?.scorecard ? `${latestScore.scorecard.overall_score?.toFixed(0) ?? "N/A"}/100 · ${latestScore.scorecard.acceptance_passed === true ? "Passed" : latestScore.scorecard.acceptance_passed === false ? "Failed" : "Indeterminate"} · ${(latestScore.scorecard.total_records || 0).toLocaleString()} records` : completed.length ? `${evaluations.length} evaluations · select a completed run to score` : "Complete a generation to enable evaluation"} expanded={expanded.includes("scoring")} onToggle={() => toggle("scoring")} actions={<>{latestScore && <button className="button-quiet" onClick={() => onNavigate("scoring", latestScore.id)}>View scorecard</button>}<button className="button-quiet" disabled={!completed.length} onClick={() => onNavigate("scoring", null)}><ClipboardCheck size={15} /> Score a run</button></>}>
          {completed.length || evaluations.length ? operationDetails("scoring") : undefined}
        </WorkspaceSection></div>
        <WorkspaceSection title="Bundles" icon={<FolderOpen size={19} />} summary={bundleCount ? `${bundleCount} ${bundleCount === 1 ? "bundle" : "bundles"} · ${completed.length + imports.length} complete` : "No generated or imported bundles yet"} expanded={expanded.includes("bundles")} onToggle={() => toggle("bundles")} actions={bundleCount > 0 && (completed.length ? <button className="button-quiet" onClick={onExport}><Download size={15} /> {isTauri() ? "Export bundle" : "Download bundle"}</button> : <button className="button-quiet" onClick={() => toggle("bundles")}><FolderOpen size={15} /> View bundles</button>)}>
          {bundleCount ? <div className="job-list">{generations.map((job) => <JobCard idPrefix="workspace-bundle" key={job.id} job={job} name={item.name} grouped sizeBytes={sizes[job.id]} api={api} onError={onError} onChanged={onChanged} />)}{imports.map((bundle) => <ImportedBundleRow key={bundle.id} bundle={bundle} api={api} onError={onError} onChanged={onChanged} />)}</div> : undefined}
        </WorkspaceSection>
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
