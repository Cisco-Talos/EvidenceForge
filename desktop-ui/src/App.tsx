import { StateMaintenance } from "./StateMaintenance";
import { type DragEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowLeft, ArrowUpRight, Bookmark, Download, FileCode2, Filter, Folder, FolderOpen, Layers3, MoreHorizontal, Play, Plus, RefreshCw, Search, Settings2, Trash2, X } from "lucide-react";
import { Dialog, DropdownMenu, Tooltip } from "radix-ui";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { CatalogItem, CodexHealth, Conversation, ItemKind, PackPublisherStatus, Project, SavedView, StudioApiError, StudioJob, type ExportProgress, type PackCreation } from "./api";
import { formatTime, shortPath } from "./components";
import { BundleLibrary } from "./BundleLibrary";
import { CopyPathButton } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { JobSections } from "./JobSections";
import { completedSuccessfully } from "./jobOutcomes";
import { SettingsView } from "./SettingsView";
import { RuntimeCleanupNotice } from "./RuntimeCleanupNotice";
import { ChatView } from "./ChatView";
import { artifactFilename, artifactTitle, draftTitle } from "./artifactNaming";
import { packNameError } from "./packName";
import { scenarioNameError } from "./scenarioName";
import { scenarioStates } from "./ScenarioStates";
import { PackLibrary } from "./PackLibrary";
import { ScenarioLibrary, type ScenarioSort } from "./ScenarioLibrary";
import { useLibraryRecall } from "./useLibraryRecall";
import { DeletePackDialog } from "./DeletePackDialog";
import { DeleteScenarioDialog } from "./DeleteScenarioDialog";
import { NewPackDialog } from "./NewPackDialog";
import { PackFilters, emptyPackFilters } from "./PackFilters";
import { ArtifactPropertiesDialog, type PropertiesSection } from "./ArtifactProperties";
import { ArtifactTitle } from "./ArtifactTitle";
import { ScenarioWorkspace, type WorkspaceTarget } from "./ScenarioWorkspace";
import { workspaceConversations } from "./workspaceConversations";
import { ImportDialog } from "./ImportDialog";
import { BundleFileBrowser, type BundleFiles } from "./BundleFileBrowser";
import { useStudio } from "./useStudio";
import { useNotice } from "./useNotice";
import "./App.css";

type Section = "scenarios" | "packs" | "bundles" | "jobs" | "settings";
type CloseProblem = { type: "checkpoint_disabled" | "confirm_delete" | "waiting"; jobIds: string[]; failures?: { id: string; detail: string }[] };

const sectionTitles: Record<Section, string> = {
  scenarios: "Scenarios", packs: "Packs",
  bundles: "Bundles", jobs: "Job center", settings: "Settings",
};

function App() {
  const studio = useStudio();
  const { api, snapshot } = studio;
  const [propertiesTarget, setPropertiesTarget] = useState<{ id: string; section: PropertiesSection } | null>(null);
  const [section, setSection] = useState<Section>("scenarios");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draftConversationId, setDraftConversationId] = useState<string | null>(null);
  const [workspaceTarget, setWorkspaceTarget] = useState<WorkspaceTarget>("overview");
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showHidden, setShowHidden] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<string[]>([]);
  const [scenarioSort, setScenarioSort] = useState<ScenarioSort>("name");
  const [packFilter, setPackFilter] = useState<"packs" | "industry_pack" | "organization_pack">("packs");
  const [packCriteria, setPackCriteria] = useState(emptyPackFilters);
  const [newPackKind, setNewPackKind] = useState<"industry_pack" | "organization_pack" | null>(null);
  const [showViews, setShowViews] = useState(false);
  const [viewName, setViewName] = useState("");
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const [commandIndex, setCommandIndex] = useState(0);
  const [searchResult, setSearchResult] = useState<{ key: string; ids: Set<string>; hits: Map<string, CatalogItem> } | null>(null);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [configurationMove, setConfigurationMove] = useState<{ entry: CatalogItem; projectId: string | null } | null>(null);
  const [projectForm, setProjectForm] = useState<{ id: string | null; name: string; description: string; overlay_enabled?: boolean; assignItemId: string | null } | null>(null);
  const [deletingScenario, setDeletingScenario] = useState<CatalogItem | null>(null);
  const [deletingPack, setDeletingPack] = useState<CatalogItem | null>(null);
  const [deletingProject, setDeletingProject] = useState<Project | null>(null);
  const [cloningItem, setCloningItem] = useState<CatalogItem | null>(null);
  const [cloneName, setCloneName] = useState("");
  const [cloneVersion, setCloneVersion] = useState("");
  const [clonePublisherStatus, setClonePublisherStatus] = useState<PackPublisherStatus | null>(null);
  const [clonePublisher, setClonePublisher] = useState("");
  const [clonePublisherDisplay, setClonePublisherDisplay] = useState("");
  const [newScenarioForm, setNewScenarioForm] = useState<{ name: string; projectId: string } | null>(null);
  const [packImportOpen, setPackImportOpen] = useState(false);
  const [renamingDraft, setRenamingDraft] = useState<Conversation | null>(null);
  const [draftName, setDraftName] = useState("");
  const [dropTargetId, setDropTargetId] = useState<string | null>(null);
  const draggedScenario = useRef<string | null>(null);
  const [sourceViewer, setSourceViewer] = useState<{ itemId: string; files: BundleFiles } | null>(null);
  const [focusJobId, setFocusJobId] = useState<string | null>(null);
  const { notice, showError: setNotice, showNotice, dismiss: dismissNotice } = useNotice();
  useEffect(() => {
    if (!snapshot || !studio.upgradeNotice) return;
    showNotice(studio.upgradeNotice);
    studio.clearUpgradeNotice();
  }, [snapshot, studio.upgradeNotice, studio.clearUpgradeNotice, showNotice]);
  const [busy, setBusy] = useState(false);
  const [closeFailed, setCloseFailed] = useState(false);
  const [closeProblem, setCloseProblem] = useState<CloseProblem | null>(null);
  const [closeChoices, setCloseChoices] = useState<Record<string, "continue" | "stop" | "">>({});
  const [editingConversation, setEditingConversation] = useState<Conversation | null>(null);
  const [editingTitle, setEditingTitle] = useState("");
  const [deletingConversation, setDeletingConversation] = useState<Conversation | null>(null);
  const [exportItem, setExportItem] = useState<CatalogItem | null>(null);
  const [exportRunId, setExportRunId] = useState("");
  const [exportProgress, setExportProgress] = useState<ExportProgress | null>(null);
  const [fixDraft, setFixDraft] = useState<{ conversationId: string; text: string } | null>(null);
  const [showReconnect, setShowReconnect] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);

  useLibraryRecall(api, snapshot?.settings.workspace, section, {
    search, project_id: selectedProjectId, show_hidden: showHidden, sort: scenarioSort, expanded_groups: expandedGroups,
    pack_kind: packFilter, publisher: packCriteria.publisher, version: packCriteria.version,
    pack_source: packCriteria.source as "" | "bundled" | "workspace",
  }, (view) => {
    setExpandedGroups(view.expanded_groups || []);
    setSearch(view.search); setShowHidden(view.show_hidden); setScenarioSort(view.sort);
    setSelectedProjectId(view.project_id === "ungrouped" || snapshot?.projects.some((project) => project.id === view.project_id) ? view.project_id : null);
    setPackFilter(view.pack_kind); setPackCriteria({ publisher: view.publisher, version: view.version, source: view.pack_source });
  }, setNotice);

  const kind = section === "scenarios" ? "scenario" : section === "packs" ? packFilter : section;
  const selectedProject = snapshot?.projects.find((project) => project.id === selectedProjectId) || null;
  const projectName = selectedProjectId === "ungrouped" ? "Ungrouped" : selectedProject?.name;
  const inLibrary = (entryKind: string | null | undefined) => !!entryKind && (section === "packs" ? entryKind !== "scenario" : entryKind === "scenario");
  const allDrafts = snapshot?.conversations.filter((chat) => !chat.item_id && inLibrary(chat.draft_kind)) || [];
  const scenarioCount = (snapshot?.items.filter((entry) => inLibrary(entry.kind) && !entry.hidden).length || 0) + allDrafts.length;
  const ungroupedCount = (snapshot?.items.filter((entry) => inLibrary(entry.kind) && !entry.hidden && !entry.project_id).length || 0) + allDrafts.filter((draft) => !draft.draft_project_id).length;
  const searchKey = `${kind}:${search.trim()}:${snapshot?.settings.search_match_limit || 5}:${snapshot?.items.filter((entry) => entry.kind === kind || kind === "packs" && entry.kind !== "scenario").map((entry) => `${entry.id}:${entry.search_revision || entry.source_sha256}`).join(";")}`;
  const library = useMemo(() => snapshot?.items.filter((entry) =>
    (entry.kind === kind || (kind === "packs" && entry.kind !== "scenario")) && (!entry.hidden || showHidden) &&
    (selectedProjectId === null || (selectedProjectId === "ungrouped" ? !entry.project_id : entry.project_id === selectedProjectId)) &&
    (kind === "scenario" || ((!packCriteria.publisher || entry.publisher === packCriteria.publisher) && (!packCriteria.version || entry.version === packCriteria.version) && (!packCriteria.source || entry.pack_source === packCriteria.source))) &&
    (!search.trim() || (searchResult?.key === searchKey
      ? searchResult.ids.has(entry.id)
      : `${artifactTitle(entry)} ${entry.name} ${entry.description} ${entry.publisher || ""} ${entry.publisher_display_name || ""} ${entry.version} ${entry.requires_evidenceforge || ""} ${entry.pack_source || ""}`.toLowerCase().includes(search.toLowerCase())))).map((entry) => search.trim() && searchResult?.key === searchKey ? searchResult.hits.get(entry.id) || entry : entry) || [],
    [snapshot, kind, search, searchKey, searchResult, selectedProjectId, packCriteria, showHidden]);
  const item = snapshot?.items.find((entry) => entry.id === selectedId) || null;
  const projectScenarios = snapshot?.items.filter((entry) => entry.kind === "scenario" && !entry.hidden && (selectedProjectId === "ungrouped" ? !entry.project_id : entry.project_id === selectedProjectId)) || [];
  const projectAttention = snapshot ? projectScenarios.filter((entry) => scenarioStates(entry, snapshot).some((state) => ["error", "warning"].includes(state.state))).length : 0;
  const projectActiveRuns = snapshot?.jobs.filter((job) => job.kind === "generation" && ["queued", "running", "paused"].includes(job.status) && projectScenarios.some((entry) => entry.path === job.scenario)).length || 0;
  const draftConversation = snapshot?.conversations.find((chat) => chat.id === draftConversationId) || null;
  const drafts = snapshot?.conversations.filter((chat) =>
    !chat.item_id && (chat.draft_kind === kind || (kind === "packs" && !!chat.draft_kind && chat.draft_kind !== "scenario")) &&
    (selectedProjectId === null || (selectedProjectId === "ungrouped" ? !chat.draft_project_id : chat.draft_project_id === selectedProjectId)) &&
    (kind === "scenario" || (!packCriteria.publisher && !packCriteria.version && packCriteria.source !== "bundled")) &&
    `${chat.draft_name || chat.title} ${chat.title}`.toLowerCase().includes(search.toLowerCase())) || [];
  const savedViews = snapshot?.views.filter((view) => section === "packs" ? view.kind !== "scenario" : view.kind === kind) || [];
  const hiddenCount = snapshot?.items.filter((entry) => (entry.kind === kind || (kind === "packs" && entry.kind !== "scenario")) && entry.hidden).length || 0;
  const conversations = selectedId ? workspaceConversations(snapshot?.conversations || [], selectedId) : [];
  const itemGenerationIds = new Set(snapshot?.jobs.filter((job) => job.kind === "generation" && job.scenario === item?.path).map((job) => job.id) || []);
  const itemJobs = snapshot?.jobs.filter((job) => item && ((job.kind === "generation" && job.scenario === item.path) || (job.kind === "evaluation" && !!job.generation_id && itemGenerationIds.has(job.generation_id)))) || [];
  function jobScenarioName(job: StudioJob): string | undefined {
    const generation = job.kind === "evaluation"
      ? snapshot?.jobs.find((candidate) => candidate.id === job.generation_id)
      : job;
    return snapshot?.items.find((entry) => entry.kind === "scenario" && entry.path === generation?.scenario)?.name;
  }
  const activeJobs = snapshot?.jobs.filter((job) => ["queued", "running", "paused"].includes(job.status)).length || 0;
  const hasPausedJobs = snapshot?.jobs.some((job) => job.status === "paused" && (job.kind === "evaluation" || job.can_resume)) || false;
  const codexHealth: CodexHealth = studio.liveState === "disconnected"
    ? { state: "disconnected", detail: "Studio service connection lost; reconnecting automatically" }
    : studio.liveState === "connecting"
      ? { state: "checking", detail: "Connecting to Studio service" }
      : snapshot?.codex_health ?? { state: "checking", detail: "Checking Codex connection" };
  const codexHealthy = codexHealth.state === "connected";
  const workingChats = snapshot?.conversations.filter((chat) => chat.active && !chat.needs_attention && codexHealthy) || [];
  const attentionChats = snapshot?.conversations.filter((chat) => chat.active && chat.needs_attention) || [];
  const uncertainChats = snapshot?.conversations.filter((chat) => chat.active && !chat.needs_attention && !codexHealthy) || [];


  const commands = [
    { id: "new:scenario", label: "New scenario", detail: "Create or import YAML", run: () => { setSection("scenarios"); setNewScenarioForm({ name: "", projectId: selectedProjectId && selectedProjectId !== "ungrouped" ? selectedProjectId : "" }); } },
    ...(item?.kind === "scenario" ? [
      { id: "action:validate", label: `Validate ${artifactTitle(item)}`, detail: "Current scenario", run: () => void validateItem() },
      { id: "action:generate", label: `Generate ${artifactTitle(item)}`, detail: "Current scenario", run: () => { setWorkspaceTarget("generation"); } },
      { id: "action:author", label: `Author ${artifactTitle(item)}`, detail: "Conversations", run: () => { if (conversations[0]) { setSelectedConversation(conversations[0].id); setWorkspaceTarget("conversations"); } else void createConversation(); } },
    ] : []),
    ...(["scenarios", "packs", "bundles", "jobs", "settings"] as Section[]).map((target) => ({
      id: `section:${target}`, label: sectionTitles[target], detail: "Navigate", run: () => {
        setSection(target); setSelectedId(null); setDraftConversationId(null);
      },
    })),
    ...(snapshot?.items || []).filter((entry) => !entry.hidden).map((entry) => ({
      id: `item:${entry.id}`, label: artifactTitle(entry),
      detail: entry.kind === "scenario" ? "Scenario" : entry.kind === "industry_pack" ? "Industry pack" : "Org pack",
      run: () => { setSection(entry.kind === "scenario" ? "scenarios" : "packs"); openItem(entry); },
    })),
    ...(snapshot?.projects || []).map((project) => ({
      id: `project:${project.id}`, label: project.name, detail: "Project", run: () => {
        setSection("scenarios"); setSelectedId(null); setDraftConversationId(null); setSelectedProjectId(project.id);
      },
    })),
  ].filter((command) => `${command.label} ${command.detail}`.toLowerCase().includes(commandQuery.trim().toLowerCase())).slice(0, 30);

  function runCommand(index: number) {
    const command = commands[index];
    if (!command) return;
    command.run();
    setCommandOpen(false);
    setCommandQuery("");
    setCommandIndex(0);
  }

  async function reconnectCodex() {
    if (!api) return;
    setReconnecting(true);
    try {
      await api.request("/v1/codex/reconnect", "POST", { interrupt_active: uncertainChats.length + attentionChats.length > 0 }, 30000);
      await studio.reload();
      setShowReconnect(false);
      showNotice("Codex reconnected. Review interrupted conversations before continuing.");
    } catch (error) { setNotice(String(error)); }
    finally { setReconnecting(false); }
  }

  function completedRuns(target: CatalogItem): StudioJob[] {
    return (snapshot?.jobs || []).filter((job) => job.kind === "generation" && job.scenario === target.path && job.status === "completed")
      .sort((a, b) => (b.started_at || 0) - (a.started_at || 0));
  }

  function openExport(target: CatalogItem) {
    const runs = completedRuns(target);
    if (!runs.length) return;
    setExportItem(target);
    setExportRunId(runs[0].id);
  }

  async function downloadBundle() {
    if (!api || !exportItem || !exportRunId) return;
    setBusy(true);
    setExportProgress(null);
    try {
      const result = await api.download(`/v1/items/${exportItem.id}/bundles/${exportRunId}.zip`, artifactFilename({ name: exportItem.name, version: exportRunId.slice(0, 8) }, "zip"), setExportProgress);
      if (result.status !== "cancelled") {
        setExportItem(null);
        showNotice(result.status === "saved" ? "ZIP saved to your chosen folder." : "Bundle ZIP download started.");
      }
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); setExportProgress(null); }
  }

  async function renameConversation() {
    if (!api || !editingConversation || !editingTitle.trim()) return;
    try {
      await api.request(`/v1/conversations/${editingConversation.id}`, "PATCH", { title: editingTitle.trim() });
      setEditingConversation(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  async function deleteConversation() {
    if (!api || !deletingConversation) return;
    try {
      await api.request(`/v1/conversations/${deletingConversation.id}`, "DELETE");
      if (selectedConversation === deletingConversation.id) setSelectedConversation(conversations.find((chat) => chat.id !== deletingConversation.id)?.id || null);
      if (draftConversationId === deletingConversation.id) setDraftConversationId(null);
      setDeletingConversation(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  async function saveProject() {
    if (!api || !projectForm || !projectForm.name.trim()) return;
    setBusy(true);
    try {
      const project = await api.request<Project>(
        projectForm.id ? `/v1/projects/${projectForm.id}` : "/v1/projects",
        projectForm.id ? "PATCH" : "POST",
        { name: projectForm.name.trim(), description: projectForm.description.trim(), ...(projectForm.overlay_enabled === undefined ? {} : { overlay_enabled: projectForm.overlay_enabled }) },
      );
      if (projectForm.assignItemId) {
        setProjectForm((current) => current ? { ...current, id: project.id } : current);
        await api.request(`/v1/items/${projectForm.assignItemId}`, "PATCH", { project_id: project.id, confirm_configuration_change: true });
      }
      setProjectForm(null);
      setSelectedProjectId(project.id);
      setSelectedId(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function assignProject(entry: CatalogItem, projectId: string | null, confirmed = false) {
    if (!api) return;
    const currentProject = snapshot?.projects.find((project) => project.id === entry.project_id);
    const nextProject = snapshot?.projects.find((project) => project.id === projectId);
    if (!confirmed && entry.kind === "scenario" && entry.project_id !== projectId && (currentProject?.overlay_enabled || nextProject?.overlay_enabled)) { setConfigurationMove({ entry, projectId }); return; }
    try {
      await api.request(`/v1/items/${entry.id}`, "PATCH", { project_id: projectId, ...(confirmed ? { confirm_configuration_change: true } : {}) });
      setConfigurationMove(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  async function setItemHidden(entry: CatalogItem, hidden: boolean) {
    if (!api) return;
    try {
      await api.request(`/v1/items/${entry.id}`, "PATCH", { hidden });
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  function toggleLibraryGroup(id: string, open: boolean) {
    setExpandedGroups((current) => current.includes(id) === open ? current : open ? [...current, id] : current.filter((key) => key !== id));
  }

  function applySavedView(view: SavedView) {
    if (view.kind !== "scenario") {
      setPackFilter(view.kind);
      setPackCriteria({ publisher: view.publisher || "", version: view.version || "", source: view.pack_source || "" });
    }
    setExpandedGroups(view.expanded_groups || []);
    setScenarioSort(view.sort || "name");
    setSearch(view.search);
    setShowHidden(view.show_hidden);
    const projectId = view.project_id && snapshot?.projects.some((project) => project.id === view.project_id)
      ? view.project_id : null;
    setSelectedProjectId(view.ungrouped ? "ungrouped" : projectId);
    setShowViews(false);
  }

  async function saveCurrentView() {
    if (!api || !viewName.trim()) return;
    setBusy(true);
    try {
      await api.request("/v1/views", "POST", {
        name: viewName.trim(), kind, search: search.trim(), folder: null,
        project_id: selectedProjectId !== "ungrouped" ? selectedProjectId : null,
        ungrouped: selectedProjectId === "ungrouped",
        show_hidden: showHidden, sort: scenarioSort, expanded_groups: expandedGroups,
        ...(section === "packs" ? { publisher: packCriteria.publisher, version: packCriteria.version, pack_source: packCriteria.source } : {}),
      });
      setViewName("");
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function deleteSavedView(view: SavedView) {
    if (!api) return;
    try {
      await api.request(`/v1/views/${encodeURIComponent(view.name)}`, "DELETE");
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  function beginScenarioDrag(event: DragEvent<HTMLElement>, entry: CatalogItem) {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData(entry.kind === "scenario" ? "application/x-evidenceforge-scenario" : "application/x-evidenceforge-item", entry.id);
    event.dataTransfer.setData("text/plain", entry.name);
    draggedScenario.current = entry.id;
  }

  function allowProjectDrop(event: DragEvent<HTMLElement>, projectId: string | null) {
    if (!draggedScenario.current && !Array.from(event.dataTransfer.types || []).some((type) => ["application/x-evidenceforge-scenario", "application/x-evidenceforge-item", "application/x-evidenceforge-draft"].includes(type))) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    setDropTargetId(projectId || "ungrouped");
  }

  function leaveProjectDrop(event: DragEvent<HTMLElement>) {
    if (event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget)) return;
    setDropTargetId(null);
  }

  function endScenarioDrag() {
    draggedScenario.current = null;
    setDropTargetId(null);
  }

  function dropIntoProject(event: DragEvent<HTMLElement>, projectId: string | null) {
    event.preventDefault();
    const itemId = event.dataTransfer.getData("application/x-evidenceforge-item") || event.dataTransfer.getData("application/x-evidenceforge-scenario") || draggedScenario.current;
    const entry = snapshot?.items.find((candidate) => candidate.id === itemId);
    const draftId = event.dataTransfer.getData("application/x-evidenceforge-draft") || draggedScenario.current;
    const draft = snapshot?.conversations.find((candidate) => candidate.id === draftId && candidate.draft_kind);
    endScenarioDrag();
    if (entry && entry.project_id !== projectId) void assignProject(entry, projectId);
    if (draft && draft.draft_project_id !== projectId) void assignDraftProject(draft, projectId);
  }

  async function deleteProject() {
    if (!api || !deletingProject) return;
    setBusy(true);
    try {
      await api.request(`/v1/projects/${deletingProject.id}`, "DELETE");
      setSelectedProjectId("ungrouped");
      setSelectedId(null);
      setDeletingProject(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  function beginScenarioClone(entry: CatalogItem) {
    const stem = entry.name || "scenario";
    setCloningItem(entry);
    setCloneName(`${stem}-copy`);
  }

  async function beginPackClone(entry: CatalogItem) {
    if (!api) return;
    const stem = entry.name || "pack";
    setCloningItem(entry);
    setCloneName(`${stem}-copy`);
    setCloneVersion(/^\d+\.\d+\.\d+$/.test(entry.version) ? entry.version : "0.1.0");
    setClonePublisherStatus(null);
    setClonePublisher("");
    setClonePublisherDisplay("");
    try {
      setClonePublisherStatus(await api.request<PackPublisherStatus>("/v1/packs/publisher"));
    } catch (error) { setCloningItem(null); setNotice(String(error)); }
  }

  async function cloneScenario() {
    if (!api || !cloningItem || !cloneName.trim()) return;
    setBusy(true);
    try {
      const cloned = await api.request<CatalogItem>(`/v1/scenarios/${cloningItem.id}/clone`, "POST", { name: cloneName.trim() });
      await studio.reload();
      setCloningItem(null);
      setSection("scenarios");
      openItem(cloned);
      showNotice(`Created ${cloned.name} with a separate authored scenario folder.`);
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function clonePack() {
    if (!api || !cloningItem || !clonePublisherStatus) return;
    setBusy(true);
    try {
      const cloned = await api.request<CatalogItem>(`/v1/packs/${cloningItem.id}/clone`, "POST", {
        name: cloneName.trim(), version: cloneVersion.trim(),
        ...(clonePublisherStatus.configured ? {} : {
          publisher: clonePublisher.trim(), publisher_display_name: clonePublisherDisplay.trim(),
        }),
      }, 190000);
      await studio.reload();
      setCloningItem(null);
      setSection("packs");
      openItem(cloned);
      showNotice(`Created local pack ${cloned.name}@${cloned.version}.`);
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  function openItem(next: CatalogItem) {
    setDraftConversationId(null);
    setSelectedId(next.id);
    setWorkspaceTarget("overview");
    setSelectedConversation(null);
    setFocusJobId(null);
  }

  function openActiveConversation(chat: Conversation) {
    if (!chat.item_id && chat.draft_kind) {
      setSection(chat.draft_kind === "scenario" ? "scenarios" : "packs");
      setSelectedId(null);
      setDraftConversationId(chat.id);
      return;
    }
    const source = snapshot?.items.find((entry) => entry.id === chat.item_id);
    if (!source) {
      setNotice("This conversation's source is not in the current workspace.");
      return;
    }
    setSection(source.kind === "scenario" ? "scenarios" : "packs");
    openItem(source);
    setSelectedConversation(chat.id);
    setWorkspaceTarget("conversations");
  }

  async function validateItem() {
    if (!api || !item) return;
    setBusy(true);
    setWorkspaceTarget("validation");
    try { await api.request("/v1/validate", "POST", { scenario_id: item.id }); }
    catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function exportPack(source: CatalogItem) {
    try {
      const result = await api!.download(`/v1/packs/${source.id}/export`, artifactFilename(source, "efpack"), setExportProgress);
      if (result.status === "saved") showNotice(`Pack saved to ${result.path}`);
    } catch (error) { setNotice(String(error)); }
    finally { setExportProgress(null); }
  }

  async function viewYaml() {
    if (!item || !api) return;
    try { setSourceViewer({ itemId: item.id, files: await api.request<BundleFiles>(`/v1/items/${item.id}/files`) }); }
    catch (error) { setNotice(String(error)); }
  }

  async function saveDraftDisplayName(displayName: string | null, name?: string) {
    if (!api || !draftConversation) return;
    await api.request(`/v1/conversations/${draftConversation.id}`, "PATCH", { draft_display_name: displayName, ...(name ? { draft_name: name } : {}) });
    await studio.reload();
    showNotice(name ? "Names saved." : "Display name saved.");
  }

  async function startGeneration() {
    if (!api || !item || snapshot?.dependencies?.[item.id]?.ready === false) return;
    setBusy(true);
    try {
      await api.request("/v1/jobs/generations", "POST", { scenario_id: item.id });
      await studio.reload();
      setWorkspaceTarget("generation");
      showNotice("Generation queued. Its progress is visible here and in Job center.");
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function createConversation() {
    if (!api || !item) return;
    try {
      const created = await api.request<Conversation>("/v1/conversations", "POST", { item_id: item.id });
      await studio.reload();
      if (created.item_id && created.item_id !== item.id) setSelectedId(created.item_id);
      setSelectedConversation(created.id);
      setWorkspaceTarget("conversations");
    } catch (error) { setNotice(String(error)); }
  }

  async function prepareEnvironmentChange(text: string) {
    if (!api || !item) return;
    const created = await api.request<Conversation>("/v1/conversations", "POST", { item_id: item.id });
    await studio.reload();
    setFixDraft({ conversationId: created.id, text });
    if (created.item_id && created.item_id !== item.id) setSelectedId(created.item_id);
    setSelectedConversation(created.id);
    setWorkspaceTarget("conversations");
  }

  async function createDraft(name?: string, projectId?: string | null, displayName?: string, packKind?: ItemKind) {
    const draftKind = section === "scenarios" ? "scenario" : packKind;
    if (!api || !draftKind || (draftKind === "scenario" && scenarioNameError(name || ""))) return;
    setBusy(true);
    try {
      const created = await api.request<Conversation>("/v1/conversations", "POST", {
        draft_kind: draftKind,
        project_id: draftKind === "scenario" ? (projectId || null) : null,
        ...(draftKind === "scenario" ? { name: name?.trim(), ...(displayName ? { display_name: displayName } : {}) } : {}),
      });
      setNewScenarioForm(null);
      await studio.reload();
      setSelectedId(null);
      setDraftConversationId(created.id);
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  async function packCreated(created: PackCreation, details: string) {
    setNewPackKind(null);
    await studio.reload();
    setSelectedId(created.item.id);
    setDraftConversationId(null);
    setSelectedConversation(created.conversation.id);
    setWorkspaceTarget("conversations");
    if (details && api) {
      try {
        await api.request(`/v1/conversations/${created.conversation.id}/turns`, "POST", { text: details }, 90000);
        await studio.reload();
      } catch (error) { setNotice(`Pack created. The first message could not be confirmed: ${String(error)}`); }
    }
  }

  async function renameDraft() {
    if (!api || !renamingDraft || scenarioNameError(draftName)) return;
    try {
      await api.request(`/v1/conversations/${renamingDraft.id}`, "PATCH", { draft_name: draftName.trim() });
      setRenamingDraft(null);
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  async function assignDraftProject(draft: Conversation, projectId: string | null) {
    if (!api) return;
    try {
      await api.request(`/v1/conversations/${draft.id}`, "PATCH", { draft_project_id: projectId });
      await studio.reload();
    } catch (error) { setNotice(String(error)); }
  }

  async function fixValidationInChat() {
    if (!api || !item) return;
    const report = (studio.validations[item.id] || snapshot?.validations[item.id]?.result)?.report;
    const findings = Array.isArray(report?.issues) ? report.issues as Record<string, unknown>[] : [];
    const summaries = findings.slice(0, 40).map((finding) => {
      const suggestion = finding.suggestion ? ` Suggested fix: ${String(finding.suggestion)}` : "";
      return `- [${String(finding.severity || "finding").toUpperCase()}] ${String(finding.field_path || "scenario")}: ${String(finding.message || "")}${suggestion}`;
    });
    const prompt = [
      "Please review and fix this scenario's validation findings. First rerun eforge validate against the current authored files so that changes to includes, packs, or overlays are accounted for. Explain the changes you plan, then update the authored files and revalidate. Do not edit generated bundles.",
      "",
      `Saved findings from the Validation panel (${findings.length}; recheck before acting):`,
      ...summaries,
      ...(findings.length > summaries.length ? [`- ${findings.length - summaries.length} more findings; rerun validation for the full list.`] : []),
    ].join("\n");
    setBusy(true);
    try {
      const created = await api.request<Conversation>("/v1/conversations", "POST", { item_id: item.id });
      setFixDraft({ conversationId: created.id, text: prompt });
      if (created.item_id && created.item_id !== item.id) setSelectedId(created.item_id);
      setSelectedConversation(created.id);
      setWorkspaceTarget("conversations");
    } catch (error) { setNotice(String(error)); }
    finally { setBusy(false); }
  }

  useEffect(() => {
    if (workspaceTarget === "conversations" && !selectedConversation && conversations.length) setSelectedConversation(conversations[0].id);
  }, [workspaceTarget, selectedConversation, conversations]);

  useEffect(() => {
    setSelectedId(null);
    setDraftConversationId(null);
    setNewPackKind(null);
  }, [snapshot?.settings.workspace]);

  useEffect(() => {
    if (!api || !search.trim() || !["scenario", "packs", "industry_pack", "organization_pack"].includes(kind)) {
      setSearchResult(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const kinds = kind === "packs" ? ["industry_pack", "organization_pack"] : [kind];
      void Promise.all(kinds.map((entryKind) => api.request<CatalogItem[]>(`/v1/items?kind=${encodeURIComponent(entryKind)}&search=${encodeURIComponent(search.trim())}`)))
        .then((results) => results.flat())
        .then((found) => { if (!cancelled) setSearchResult({ key: searchKey, ids: new Set(found.map((entry) => entry.id)), hits: new Map(found.map((entry) => [entry.id, entry])) }); })
        .catch((error) => { if (!cancelled) setNotice(`Search failed: ${String(error)}`); });
    }, 180);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [api, kind, search, searchKey, snapshot?.settings.workspace]);

  useEffect(() => {
    if (!draftConversationId || !draftConversation?.item_id) return;
    const authored = snapshot?.items.find((entry) => entry.id === draftConversation.item_id);
    if (!authored) return;
    setSection(authored.kind === "scenario" ? "scenarios" : "packs");
    setSelectedId(authored.id);
    setSelectedConversation(draftConversation.id);
    setWorkspaceTarget("conversations");
    setDraftConversationId(null);
  }, [draftConversationId, draftConversation, snapshot?.items]);

  const submitClose = useCallback(async (options?: { confirm_delete?: boolean; generation_exceptions?: Record<string, string> }) => {
    if (!api) return;
    if (!snapshot) {
      await api.request("/v1/session/detach", "POST").catch(() => undefined);
      await invoke("studio_exit");
      return;
    }
    try {
      const result = await api.request<{ status: string }>("/v1/session/close", "POST", options, 3000);
      if (result.status === "waiting") setCloseProblem({ type: "waiting", jobIds: [] });
      else await invoke("studio_exit");
    } catch (error) {
      const detail = error instanceof StudioApiError ? error.detail as { reason?: string; job_ids?: string[] } : null;
      if (detail?.reason === "checkpoint_disabled") {
        setCloseProblem({ type: "checkpoint_disabled", jobIds: detail.job_ids || [] });
      } else if (detail?.reason === "confirm_delete") {
        setCloseProblem({ type: "confirm_delete", jobIds: detail.job_ids || [] });
      } else if (snapshot.settings.quit.action === "continue") {
        // The detached controller keeps running the default pipeline even if the UI lost contact.
        await invoke("studio_exit");
      } else {
        setCloseFailed(true);
        setNotice(`Could not hand off quit actions: ${String(error)}`);
      }
    }
  }, [api, snapshot]);

  const closeHandler = useRef(submitClose);
  closeHandler.current = submitClose;

  useEffect(() => {
    if (!api || !window.__TAURI_INTERNALS__) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void getCurrentWindow().onCloseRequested(async (event) => {
      event.preventDefault();
      await closeHandler.current();
    }).then((dispose) => { if (disposed) dispose(); else unlisten = dispose; })
      .catch((error) => setNotice(`Could not register close handling: ${String(error)}`));
    return () => { disposed = true; unlisten?.(); };
  }, [Boolean(api), Boolean(snapshot)]);

  useEffect(() => {
    if (!api || closeProblem?.type !== "waiting") return;
    const timer = setInterval(() => {
      void api.request<{ ready: boolean; running: string[]; failures: { id: string; detail: string }[] }>("/v1/session/close-status")
        .then((status) => {
          if (status.ready) void invoke("studio_exit");
          else setCloseProblem({ type: "waiting", jobIds: status.running, failures: status.failures });
        })
        .catch((error) => setNotice(`Could not check close progress: ${String(error)}`));
    }, 750);
    return () => clearInterval(timer);
  }, [api, closeProblem?.type]);

  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === ",") {
        event.preventDefault(); setSelectedId(null); setDraftConversationId(null); setSection("settings");
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); setCommandOpen(true); setCommandQuery(""); setCommandIndex(0);
      }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, []);

  if (studio.maintenance) return <StateMaintenance status={studio.maintenance} requestError={studio.error} onRetry={() => void studio.recoverState()} onRestore={() => void studio.recoverState(true)} onWorkspace={(path) => void studio.selectRecoveryWorkspace(path)} />;
  if (!snapshot || !api) return <div className="boot-screen"><img className="boot-logo" src="/brand/evidenceforge-dark.png" alt="EvidenceForge" /><h1>Studio</h1><p>{studio.error || "Connecting to the local service…"}</p><button onClick={() => window.location.reload()}>Retry</button></div>;

  const showLibrary = ["scenarios", "packs"].includes(section);
  return <Tooltip.Provider><div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><img className="brand-logo" src="/brand/evidenceforge-dark.png" alt="EvidenceForge" /><img className="brand-mini" src="/brand/icon-32.png" alt="" /><small>STUDIO</small></div>
      <nav className="primary-nav" aria-label="Main navigation">
        <button className={section === "scenarios" ? "selected" : ""} onClick={() => { setSection("scenarios"); setSelectedId(null); setDraftConversationId(null); }}><FileCode2 size={18} /> Scenarios</button>
        <button className={section === "packs" ? "selected" : ""} onClick={() => { setSection("packs"); setSelectedId(null); setDraftConversationId(null); }}><Layers3 size={18} /> Packs</button>
        <button className={section === "bundles" ? "selected" : ""} onClick={() => { setSection("bundles"); setSelectedId(null); setDraftConversationId(null); }}><FolderOpen size={18} /> Bundles</button>
        <div className="nav-rule" />
        <button className={section === "jobs" ? "selected" : ""} onClick={() => { setSection("jobs"); setSelectedId(null); setDraftConversationId(null); }}><Activity size={18} /> Job center {activeJobs > 0 && <span className="nav-count">{activeJobs}</span>}</button>
      </nav>
      <div className="sidebar-bottom"><button className={section === "settings" ? "selected" : ""} onClick={() => { setSection("settings"); setSelectedId(null); setDraftConversationId(null); }}><Settings2 size={18} /> Settings</button><span>LOCAL STUDIO · MAC & LINUX</span></div>
    </aside>
    <main className={`main-area ${showLibrary && ((item && workspaceTarget === "conversations") || draftConversationId) ? "chat-main" : ""}`}>
      <header className="topbar"><div className="topbar-title">{item || draftConversationId ? <><button className="back-link" onClick={() => { setSelectedId(null); setDraftConversationId(null); }}><ArrowLeft size={16} /> {sectionTitles[section]}</button><span className="breadcrumb-slash">/</span><strong>{item ? artifactTitle(item) : draftConversation ? draftTitle(draftConversation) : "New draft"}</strong></> : <strong>{sectionTitles[section]}</strong>}</div><div className="topbar-actions"><button className="icon-button" title="Open command menu (⌘K / Ctrl+K)" aria-label="Open command menu" onClick={() => { setCommandOpen(true); setCommandQuery(""); setCommandIndex(0); }}><Search size={17} /></button>{showLibrary && <button className="icon-button" title="Refresh library" aria-label="Refresh library" onClick={() => void api.request("/v1/library/refresh", "POST").then(studio.reload).catch((error) => setNotice(String(error)))}><RefreshCw size={17} /></button>}<Tooltip.Root><Tooltip.Trigger asChild><button className={`codex-indicator ${codexHealth.state}`} aria-label={`Codex ${codexHealth.state}: ${codexHealth.detail}`} onClick={() => studio.liveState === "disconnected" ? showNotice("Studio is reconnecting automatically.") : setShowReconnect(true)}><span className="codex-indicator-dot" /></button></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="studio-tooltip" sideOffset={7}><strong>Codex {codexHealth.state}</strong><span>{codexHealth.detail}</span><span className="tooltip-action">{studio.liveState === "disconnected" ? "Reconnecting automatically" : "Click to reconnect"}</span></Tooltip.Content></Tooltip.Portal></Tooltip.Root></div></header>

      <RuntimeCleanupNotice report={snapshot.runtime_cleanup} />
      {showLibrary && !item && !draftConversationId && <div className="page library-page">
        <div className="page-intro"><div><span className="eyebrow">YOUR WORKSPACE</span><h1>{sectionTitles[section]}</h1><p>{section === "scenarios" ? "Find a scenario and pick up where you left off." : "Reusable environments for realistic scenarios."}</p></div>{section === "scenarios" ? <button className="button-primary" disabled={busy} onClick={() => setNewScenarioForm({ name: "", projectId: selectedProjectId && selectedProjectId !== "ungrouped" ? selectedProjectId : "" })}><Plus size={17} /> New scenario</button> : <div className="library-pack-actions"><button className="button-quiet" onClick={() => setPackImportOpen(true)}><Download size={16} /> Import packs</button><DropdownMenu.Root><DropdownMenu.Trigger className="button-primary" disabled={busy}><Plus size={17} /> New pack</DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={5}><DropdownMenu.Item onSelect={() => setNewPackKind("industry_pack")}>Industry pack</DropdownMenu.Item><DropdownMenu.Item onSelect={() => setNewPackKind("organization_pack")}>Organization pack</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root></div>}</div>
        <div className="project-browser">
          {<aside className="project-rail" aria-label="Projects"><div className="project-rail-heading"><span>PROJECTS</span><button className="icon-button" aria-label="New project" title="New project" onClick={() => setProjectForm({ id: null, name: "", description: "", assignItemId: null })}><Plus size={16} /></button></div>
            <button className={`project-nav-row ${selectedProjectId === null ? "active" : ""}`} aria-label={section === "packs" ? "All packs" : "All scenarios"} onClick={() => setSelectedProjectId(null)}><Layers3 size={16} /><span>{section === "packs" ? "All packs" : "All scenarios"}</span><small>{scenarioCount}</small></button>
            {snapshot.projects.map((project) => <div className={`project-nav-entry ${selectedProjectId === project.id ? "active" : ""} ${dropTargetId === project.id ? "drop-target" : ""}`} key={project.id} onDragOver={(event) => allowProjectDrop(event, project.id)} onDragLeave={leaveProjectDrop} onDrop={(event) => dropIntoProject(event, project.id)}><button className="project-nav-row" aria-label={`Open project ${project.name}`} onClick={() => setSelectedProjectId(project.id)}><Folder size={16} /><span>{project.name}</span><small>{snapshot.items.filter((entry) => inLibrary(entry.kind) && !entry.hidden && entry.project_id === project.id).length + allDrafts.filter((draft) => draft.draft_project_id === project.id).length}</small></button><DropdownMenu.Root><DropdownMenu.Trigger className="icon-button project-menu-trigger" aria-label={`Options for project ${project.name}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4}><DropdownMenu.Item onSelect={() => setProjectForm({ id: project.id, name: project.name, description: project.description, overlay_enabled: project.overlay_enabled, assignItemId: null })}>Edit project</DropdownMenu.Item><DropdownMenu.Item onSelect={() => setDeletingProject(project)}>Delete project</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root></div>)}
            <button className={`project-nav-row ${selectedProjectId === "ungrouped" ? "active" : ""} ${dropTargetId === "ungrouped" ? "drop-target" : ""}`} aria-label="Ungrouped" onClick={() => setSelectedProjectId("ungrouped")} onDragOver={(event) => allowProjectDrop(event, null)} onDragLeave={leaveProjectDrop} onDrop={(event) => dropIntoProject(event, null)}><FolderOpen size={16} /><span>Ungrouped</span><small>{ungroupedCount}</small></button>
          </aside>}
          <div className="project-library">
            {selectedProjectId !== null && <div className="project-overview"><div><span className="eyebrow">{selectedProject ? "PROJECT" : "SCENARIOS"}</span><h2>{projectName || "Project"}</h2><p>{selectedProject ? selectedProject.description || `Your ${section} grouped for this work.` : `${section === "packs" ? "Packs" : "Scenarios"} that have not been assigned to a project.`}</p></div><div className="project-overview-stats">{section === "scenarios" && <><span>{projectAttention} need attention</span><span>{projectActiveRuns} active runs</span></>}<span className="project-total">{library.length + drafts.length} {section === "packs" ? library.length + drafts.length === 1 ? "pack" : "packs" : library.length + drafts.length === 1 ? "scenario" : "scenarios"}</span></div></div>}
            <div className="library-toolbar">

              <div className="search-box"><Search size={17} /><input placeholder={section === "packs" ? "Search name, author, version, or YAML…" : "Search scenarios…"} value={search} onChange={(event) => setSearch(event.target.value)} aria-label={`Search ${sectionTitles[section].toLowerCase()}`} /></div>
              {section === "packs" && <PackFilters items={snapshot.items.filter((entry) => entry.kind !== "scenario")} kind={packFilter} values={packCriteria} showHidden={showHidden} onKind={setPackFilter} onChange={setPackCriteria} onHidden={setShowHidden} onReset={() => { setPackFilter("packs"); setPackCriteria(emptyPackFilters); setShowHidden(false); }} />}

              {section === "scenarios" && <select className="library-sort" aria-label="Sort scenarios" value={scenarioSort} onChange={(event) => setScenarioSort(event.target.value as ScenarioSort)}><option value="name">Name A–Z</option><option value="updated">Recently updated</option><option value="project">Project A–Z</option></select>}
              {section === "scenarios" && hiddenCount > 0 && <button className={`hidden-filter ${showHidden ? "active" : ""}`} aria-label={showHidden ? "Hide hidden items" : "Show hidden items"} title={showHidden ? "Hide hidden items again" : "Include hidden items in this library"} onClick={() => setShowHidden(!showHidden)}><Filter size={15} /> {showHidden ? "Showing hidden" : `Hidden (${hiddenCount})`}</button>}
              <button className={`icon-button saved-views-toggle ${savedViews.length ? "has-views" : ""}`} aria-label="Saved views" title="Saved views" onClick={() => setShowViews(true)}><Bookmark size={17} /></button>
              <span className="result-count">{library.length + drafts.length} {library.length + drafts.length === 1 ? "item" : "items"}</span>
            </div>
            {section === "packs" ? <PackLibrary onProperties={(entry) => setPropertiesTarget({ id: entry.id, section: "general" })} artifactGroups={snapshot.artifact_groups} expandedGroups={expandedGroups} onToggleGroup={toggleLibraryGroup} items={library} drafts={drafts} projects={snapshot.projects} busy={busy} onOpen={openItem} onOpenDraft={(draft) => setDraftConversationId(draft.id)} onNew={setNewPackKind} onClone={(entry) => void beginPackClone(entry)} onExport={(entry) => void exportPack(entry)} onHide={(entry) => void setItemHidden(entry, !entry.hidden)} onMove={(entry, projectId) => void assignProject(entry, projectId)} onMoveDraft={(draft, projectId) => void assignDraftProject(draft, projectId)} onNewProject={(entry) => setProjectForm({ id: null, name: "", description: "", assignItemId: entry.id })} onDelete={setDeletingPack} onDeleteDraft={setDeletingConversation} onDragStart={beginScenarioDrag} onDraftDragStart={(event, draft) => { event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData("application/x-evidenceforge-draft", draft.id); event.dataTransfer.setData("text/plain", draftTitle(draft)); draggedScenario.current = draft.id; }} onDragEnd={endScenarioDrag} /> : <>
            {library.length + drafts.length ? <ScenarioLibrary onProperties={(entry) => setPropertiesTarget({ id: entry.id, section: "general" })} expandedGroups={expandedGroups} onToggleGroup={toggleLibraryGroup} dropTargetId={dropTargetId} onProjectDragOver={allowProjectDrop} onProjectDragLeave={leaveProjectDrop} onProjectDrop={dropIntoProject} items={library} drafts={drafts} snapshot={snapshot} api={api} sort={scenarioSort} onOpen={openItem} onOpenDraft={(draft) => setDraftConversationId(draft.id)} onClone={beginScenarioClone} onExport={openExport} onUnavailableExport={() => showNotice("Generate a run before exporting its bundle.")} onDelete={setDeletingScenario} onHide={(entry) => void setItemHidden(entry, !entry.hidden)} onMove={(entry, projectId) => void assignProject(entry, projectId)} onMoveDraft={(draft, projectId) => void assignDraftProject(draft, projectId)} onNewProject={(entry) => setProjectForm({ id: null, name: "", description: "", assignItemId: entry.id })} onRenameDraft={(draft) => { setRenamingDraft(draft); setDraftName(draftTitle(draft)); }} onDeleteDraft={setDeletingConversation} onDragStart={beginScenarioDrag} onDraftDragStart={(event, draft) => { event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData("application/x-evidenceforge-draft", draft.id); event.dataTransfer.setData("text/plain", draftTitle(draft)); draggedScenario.current = draft.id; }} onDragEnd={endScenarioDrag} /> : <div className="empty-panel tall"><FolderOpen size={30} /><h3>{search ? "No matches" : selectedProject ? "No scenarios in this project" : "Nothing here yet"}</h3><p>{search ? "Try another search." : selectedProject ? "Drag a scenario here or use its project menu." : "Add or import a scenario to start building your library."}</p></div>}
            </>}
          </div>
        </div>
      </div>}

      {showLibrary && !item && draftConversation && <div className="draft-page"><div className="draft-banner"><div><span className="eyebrow">AUTHORING DRAFT</span>{draftConversation.draft_kind === "scenario" ? <ArtifactTitle key={draftConversation.id} name={draftConversation.draft_name || "New scenario"} displayName={draftConversation.draft_display_name} api={api} source={{ context: { kind: "scenario", name: draftConversation.draft_name || "new-scenario" } }} onSave={saveDraftDisplayName} disabled={draftConversation.active} /> : <strong>{draftConversation.draft_kind === "industry_pack" ? "New industry pack" : "New organization pack"}</strong>}{draftConversation.draft_path ? <div className="path-with-copy draft-target"><span className="path-value" title={draftConversation.draft_path}>Target: {shortPath(draftConversation.draft_path)}</span><CopyPathButton path={draftConversation.draft_path} label="Copy draft path" onError={setNotice} /></div> : <span>The authored file will appear in this library.</span>}</div><button className="button-quiet" disabled={draftConversation.active} onClick={() => setDeletingConversation(draftConversation)}>Delete draft</button></div><ChatView item={{ name: draftConversation.draft_kind === "scenario" ? "New scenario" : "New pack", kind: draftConversation.draft_kind || "scenario" }} conversation={draftConversation} codexHealth={codexHealth} api={api} subscribeEvents={studio.subscribeEvents} onRenamed={studio.reload} onError={setNotice} /></div>}

      {showLibrary && item && <ScenarioWorkspace onProperties={(section = "general") => setPropertiesTarget({ id: item.id, section })} key={item.id} item={item} snapshot={snapshot} conversations={conversations} selectedConversation={selectedConversation} target={workspaceTarget} jobs={itemJobs} api={api} codexHealth={codexHealth} busy={busy} validation={studio.validations[item.id] || snapshot.validations[item.id]?.result} focusJobId={focusJobId} initialDraft={fixDraft?.conversationId === selectedConversation ? fixDraft.text : undefined} subscribeEvents={studio.subscribeEvents}
        onNavigate={(target, jobId) => { setWorkspaceTarget(target); if (jobId !== undefined) setFocusJobId(jobId); }}
        onOpenConversation={(chat) => { setSelectedConversation(chat.id); setWorkspaceTarget("conversations"); }}
        onCreateConversation={() => void createConversation()} onRenameConversation={(chat) => { setEditingConversation(chat); setEditingTitle(chat.title); }} onDeleteConversation={setDeletingConversation}
        onProjectChange={(id) => void assignProject(item, id)} onClone={() => item.kind === "scenario" ? beginScenarioClone(item) : void beginPackClone(item)} onExportPack={() => void exportPack(item)} onDeleteScenario={() => setDeletingScenario(item)} onDeletePack={() => setDeletingPack(item)} onHidden={() => void setItemHidden(item, !item.hidden)} onViewYaml={() => void viewYaml()} onImportPacks={() => setPackImportOpen(true)} onOpenPack={(entry) => { setSection("packs"); openItem(entry); }} onGenerate={startGeneration} onValidate={() => void validateItem()} onFix={() => void fixValidationInChat()} onPrepare={prepareEnvironmentChange} onDraftSubmitted={(conversationId) => setFixDraft((current) => current?.conversationId === conversationId ? null : current)} onChanged={studio.reload} onOpenArtifact={async (path) => { const items = await api.request<CatalogItem[]>("/v1/items"); const found = items.find((entry) => entry.path === path); if (found) { setSection(found.kind === "scenario" ? "scenarios" : "packs"); openItem(found); } }} onError={setNotice} />}

      {section === "jobs" && <div className="page"><div className="page-intro"><div><span className="eyebrow">ALL OPERATIONS</span><h1>Job center</h1><p>Track generations, evaluations, and active authoring turns.</p></div>{hasPausedJobs && <button className="button-quiet" onClick={() => void api.request("/v1/jobs/resume", "POST", {}).catch((error) => setNotice(String(error)))}><Play size={16} /> Resume paused jobs</button>}</div><div className="jobs-summary"><div><strong>{snapshot.jobs.filter((job) => job.status === "running").length}</strong><span>Running jobs</span></div><div><strong>{snapshot.jobs.filter((job) => job.status === "queued").length}</strong><span>Queued jobs</span></div><div><strong>{snapshot.jobs.filter((job) => completedSuccessfully(job) && !snapshot.removed_job_ids?.includes(job.id)).length}</strong><span>Completed jobs</span></div><div aria-label={`${workingChats.length} active chats`}><strong>{workingChats.length}</strong><span>Active chats</span></div>{attentionChats.length > 0 && <div aria-label={`${attentionChats.length} chats need input`}><strong>{attentionChats.length}</strong><span>Need input</span></div>}{uncertainChats.length > 0 && <div aria-label={`${uncertainChats.length} chats need reconnection`}><strong>{uncertainChats.length}</strong><span>Connection uncertain</span></div>}</div>{(workingChats.length > 0 || attentionChats.length > 0 || uncertainChats.length > 0) && <section className="chat-activity surface"><div className="surface-heading"><h2>Authoring activity</h2><span className="eyebrow">LIVE</span></div>{[...workingChats, ...attentionChats, ...uncertainChats].map((chat) => <button className="chat-activity-row" key={chat.id} onClick={() => openActiveConversation(chat)}><span className={chat.needs_attention ? "attention-dot" : "active-pulse"} /><span><strong>{chat.title}</strong><small>{snapshot.items.find((entry) => entry.id === chat.item_id)?.name || "Draft"}</small></span><em>{chat.needs_attention ? "Needs input" : !codexHealthy ? "Connection uncertain" : "Working"}</em><ArrowUpRight size={16} /></button>)}</section>}{snapshot.jobs.length ? <JobSections jobs={snapshot.jobs} removedJobIds={snapshot.removed_job_ids || []} manageHistory nameFor={jobScenarioName} api={api} onError={setNotice} onChanged={studio.reload} /> : <div className="empty-panel"><Activity size={28} /><h3>No jobs yet</h3><p>Start a generation from a scenario workspace.</p></div>}</div>}
      {section === "bundles" && <BundleLibrary snapshot={snapshot} api={api} onError={setNotice} onChanged={studio.reload} onOpenScenario={(entry) => { setSection("scenarios"); openItem(entry); }} />}
      {propertiesTarget && snapshot.items.find((entry) => entry.id === propertiesTarget.id) && <ArtifactPropertiesDialog key={`properties-${propertiesTarget.id}`} item={snapshot.items.find((entry) => entry.id === propertiesTarget.id)!} initialSection={propertiesTarget.section} snapshot={snapshot} api={api} onClose={() => setPropertiesTarget(null)} onChanged={studio.reload} onProjectChange={(projectId) => { const entry = snapshot.items.find((entry) => entry.id === propertiesTarget.id); if (entry) void assignProject(entry, projectId); }} onOpen={async (path) => { const entries = await api.request<CatalogItem[]>("/v1/items"); const found = entries.find((entry) => entry.path === path); if (found) { setSection(found.kind === "scenario" ? "scenarios" : "packs"); openItem(found); } }} />}
      {section === "settings" && <div className="page settings-page"><div className="page-intro"><div><span className="eyebrow">PREFERENCES</span><h1>Settings</h1><p>Keep your workspace and tools ready for the next task.</p></div></div><SettingsView settings={snapshot.settings} paths={snapshot.paths} runtimeCleanup={snapshot.runtime_cleanup} api={api} onSaved={studio.reload} onError={setNotice} /></div>}
      {showReconnect && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Reconnect Codex"><h2>Reconnect Codex</h2><p>{codexHealth.detail}</p>{uncertainChats.length + attentionChats.length > 0 && <p>Reconnecting will interrupt {uncertainChats.length + attentionChats.length} active {uncertainChats.length + attentionChats.length === 1 ? "turn" : "turns"}. Their conversation history remains available for review.</p>}<div className="close-modal-actions"><button className="button-quiet" onClick={() => setShowReconnect(false)}>Cancel</button><button className="button-primary" disabled={reconnecting} onClick={() => void reconnectCodex()}><RefreshCw size={16} /> {reconnecting ? "Reconnecting…" : "Reconnect"}</button></div></div></div>}
      {sourceViewer && <BundleFileBrowser jobId={sourceViewer.itemId} files={sourceViewer.files} api={api} kind="items" onClose={() => setSourceViewer(null)} onError={setNotice} />}
      {newScenarioForm && <ImportDialog kind="scenario" initialProjectId={newScenarioForm.projectId} projects={snapshot.projects} api={api} creating={busy} onCreate={createDraft} onClose={() => setNewScenarioForm(null)} onImported={async (imported) => { await studio.reload(); setNewScenarioForm(null); if (imported) openItem(imported); showNotice("Scenario imported."); }} />}
      {newPackKind && <NewPackDialog kind={newPackKind} initialProjectId={selectedProjectId && selectedProjectId !== "ungrouped" ? selectedProjectId : ""} projects={snapshot.projects} api={api} onClose={() => setNewPackKind(null)} onCreated={packCreated} />}
      {packImportOpen && <ImportDialog kind="pack" api={api} projects={snapshot.projects} initialProjectId={selectedProjectId && selectedProjectId !== "ungrouped" ? selectedProjectId : ""} onClose={() => setPackImportOpen(false)} onImported={async () => { await studio.reload(); setPackImportOpen(false); showNotice("Pack import complete. Dependency checks refreshed."); }} />}
      {renamingDraft && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Rename scenario" onSubmit={(event) => { event.preventDefault(); void renameDraft(); }}><h2>Rename scenario</h2><label className="modal-field">Scenario Name<input autoFocus aria-label="Scenario Name" name="scenario-name" autoComplete="off" aria-invalid={!!draftName && !!scenarioNameError(draftName)} aria-describedby={draftName && scenarioNameError(draftName) ? "draft-name-error" : undefined} value={draftName} onChange={(event) => setDraftName(event.target.value)} /></label>{draftName && scenarioNameError(draftName) && <p id="draft-name-error" className="field-error" role="status">{scenarioNameError(draftName)}</p>}<div className="close-modal-actions"><button type="button" className="button-quiet" onClick={() => setRenamingDraft(null)}>Cancel</button><button type="submit" className="button-primary" disabled={!!scenarioNameError(draftName)}>Save name</button></div></form></div>}
      {commandOpen && <div className="modal-backdrop"><div className="command-modal" role="dialog" aria-modal="true" aria-label="Command menu"><div className="command-search"><Search size={19} /><input autoFocus aria-label="Search commands" placeholder="Go to a scenario, project, or page…" value={commandQuery} onChange={(event) => { setCommandQuery(event.target.value); setCommandIndex(0); }} onKeyDown={(event) => { if (event.key === "Escape") setCommandOpen(false); else if (event.key === "ArrowDown") { event.preventDefault(); setCommandIndex((current) => Math.min(commands.length - 1, current + 1)); } else if (event.key === "ArrowUp") { event.preventDefault(); setCommandIndex((current) => Math.max(0, current - 1)); } else if (event.key === "Enter") { event.preventDefault(); runCommand(commandIndex); } }} /><kbd>ESC</kbd></div><div className="command-results" role="listbox" aria-label="Commands">{commands.length ? commands.map((command, index) => <button key={command.id} role="option" aria-selected={commandIndex === index} className={commandIndex === index ? "active" : ""} onMouseEnter={() => setCommandIndex(index)} onClick={() => runCommand(index)}><span>{command.label}</span><small>{command.detail}</small></button>) : <p>No matching commands.</p>}</div><div className="command-footer">↑ ↓ to select · Enter to open · Esc to close</div></div></div>}
      {showViews && showLibrary && !item && !draftConversationId && <div className="modal-backdrop"><div className="close-modal saved-views-modal" role="dialog" aria-modal="true" aria-label="Saved views"><div className="saved-views-heading"><div><h2>Saved views</h2><p>Return to a library search, its filters, and expanded groups.</p></div><button className="icon-button" aria-label="Close saved views" onClick={() => setShowViews(false)}><X size={17} /></button></div><div className="saved-views-list">{savedViews.length ? savedViews.map((view) => <div className="saved-view-row" key={view.name}><button className="saved-view-open" aria-label={`Apply saved view ${view.name}`} onClick={() => applySavedView(view)}><Bookmark size={16} /><span><strong>{view.name}</strong><small>{[view.search ? `Search: ${view.search}` : "All items", view.ungrouped ? "Ungrouped" : snapshot.projects.find((project) => project.id === view.project_id)?.name, view.publisher ? `Author: ${view.publisher}` : null, view.version, view.pack_source, view.show_hidden ? "Includes hidden" : null].filter(Boolean).join(" · ")}</small></span></button><button className="icon-button" aria-label={`Delete saved view ${view.name}`} title={`Delete ${view.name}`} onClick={() => void deleteSavedView(view)}><Trash2 size={16} /></button></div>) : <p className="muted">No saved views for this library yet.</p>}</div><form className="saved-view-create" onSubmit={(event) => { event.preventDefault(); void saveCurrentView(); }}><label className="modal-field">Name for current view<input aria-label="Saved view name" maxLength={80} value={viewName} onChange={(event) => setViewName(event.target.value)} placeholder="For example, active investigations" /></label><button className="button-primary" type="submit" disabled={busy || !viewName.trim()}><Plus size={16} /> Save view</button></form></div></div>}
      {notice && <div className={`toast toast-${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}><span>{notice.message}</span>{closeFailed && <button className="button-quiet" onClick={() => void invoke("studio_exit")}>Force close</button>}<button className="icon-button" aria-label="Dismiss message" onClick={() => { dismissNotice(); setCloseFailed(false); }}><X size={16} /></button></div>}
      {exportItem && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label={isTauri() ? "Export scenario bundle" : "Download scenario bundle"}><h2>{isTauri() ? "Export" : "Download"} {artifactTitle(exportItem)}</h2><p>Choose a completed run. The ZIP includes its logs, artifacts, ground truth, and resolved scenario, plus the current authored YAML and notes.</p><label className="modal-field">Run<select aria-label={isTauri() ? "Run to export" : "Run to download"} value={exportRunId} onChange={(event) => setExportRunId(event.target.value)}>{completedRuns(exportItem).map((run) => <option key={run.id} value={run.id}>{formatTime(run.started_at || 0)} · {run.id.slice(0, 8)}</option>)}</select></label>{busy && isTauri() && <ExportStatus progress={exportProgress} api={api!} onError={(error) => setNotice(error)} />}<div className="close-modal-actions"><button className="button-quiet" onClick={() => setExportItem(null)} disabled={busy}>Cancel</button><button className="button-primary" onClick={() => void downloadBundle()} disabled={busy}><Download size={16} /> {busy ? "Preparing ZIP…" : isTauri() ? "Export ZIP" : "Download ZIP"}</button></div></div></div>}
      {cloningItem?.kind === "scenario" && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Clone scenario" onSubmit={(event) => { event.preventDefault(); void cloneScenario(); }}><h2>Clone {artifactTitle(cloningItem)}</h2><p>Copy this scenario’s authored files into a new folder. Conversations, generated runs, and evaluations stay with the original. The copy joins the same project.</p><label className="modal-field">New scenario name<input autoFocus aria-label="New scenario name" name="scenario-clone-name" autoComplete="off" value={cloneName} onChange={(event) => setCloneName(event.target.value)} /></label><p className="muted small">Use letters, digits, hyphens, or underscores.</p><div className="close-modal-actions"><button type="button" className="button-quiet" onClick={() => setCloningItem(null)} disabled={busy}>Cancel</button><button type="submit" className="button-primary" disabled={busy || !!scenarioNameError(cloneName.trim())}>{busy ? "Cloning…" : "Clone scenario"}</button></div></form></div>}
      {cloningItem && cloningItem.kind !== "scenario" && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Clone pack" onSubmit={(event) => { event.preventDefault(); void clonePack(); }}><h2>Clone {artifactTitle(cloningItem)}</h2><p>Create a validated, editable pack in this workspace. Choose its name and version; the copy uses your publisher namespace.</p><label className="modal-field">Pack name<input autoFocus aria-label="Pack name" name="pack-clone-name" autoComplete="off" value={cloneName} onChange={(event) => setCloneName(event.target.value)} /></label><label className="modal-field">Pack version<input aria-label="Pack version" name="pack-clone-version" autoComplete="off" value={cloneVersion} onChange={(event) => setCloneVersion(event.target.value)} /></label>{clonePublisherStatus === null ? <p className="muted">Checking publisher identity…</p> : clonePublisherStatus.configured ? <p className="muted">Publisher: {clonePublisherStatus.publisher_display_name} ({clonePublisherStatus.publisher}, {clonePublisherStatus.scope} scope)</p> : <><p className="muted">Pack copies need a publisher identity. This will be saved for this workspace.</p><label className="modal-field">Publisher ID<input aria-label="Publisher ID" name="pack-publisher-id" autoComplete="off" value={clonePublisher} onChange={(event) => setClonePublisher(event.target.value)} /></label><label className="modal-field">Publisher display name<input aria-label="Publisher display name" name="pack-publisher-display-name" autoComplete="off" value={clonePublisherDisplay} onChange={(event) => setClonePublisherDisplay(event.target.value)} /></label></>}<div className="close-modal-actions"><button type="button" className="button-quiet" onClick={() => setCloningItem(null)} disabled={busy}>Cancel</button><button type="submit" className="button-primary" disabled={busy || !clonePublisherStatus || !!packNameError(cloneName.trim()) || !/^\d+\.\d+\.\d+$/.test(cloneVersion.trim()) || (!clonePublisherStatus.configured && (!/^[a-z0-9][a-z0-9-]*$/.test(clonePublisher.trim()) || !clonePublisherDisplay.trim()))}>{busy ? "Cloning…" : "Clone pack"}</button></div></form></div>}
      {projectForm && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label={projectForm.id ? "Edit project" : "New project"} onSubmit={(event) => { event.preventDefault(); void saveProject(); }}><h2>{projectForm.id ? "Edit project" : "New project"}</h2><p>Projects group scenarios and packs in this workspace. Their files stay where they are.</p><label className="modal-field">Project Name<input autoFocus aria-label="Project Name" name="project-name" autoComplete="off" maxLength={80} value={projectForm.name} onChange={(event) => setProjectForm({ ...projectForm, name: event.target.value })} /></label><label className="modal-field">Description<textarea aria-label="Project description" maxLength={240} rows={3} value={projectForm.description} onChange={(event) => setProjectForm({ ...projectForm, description: event.target.value })} /></label><label className="modal-field configuration-toggle" title="Applies this project’s configuration directory after workspace defaults to every assigned scenario. Existing runs keep their captured inputs."><span><input type="checkbox" checked={projectForm.overlay_enabled || false} onChange={(event) => setProjectForm({ ...projectForm, overlay_enabled: event.target.checked })} /> Use project configuration</span><small>Shared by this project’s scenarios. Existing runs keep their captured inputs.</small></label>{projectForm.assignItemId && <p className="muted">The selected item will be added to this project.</p>}<div className="close-modal-actions"><button type="button" className="button-quiet" onClick={() => setProjectForm(null)}>Cancel</button><button type="submit" className="button-primary" disabled={busy || !projectForm.name.trim()}>{busy ? "Saving…" : projectForm.id ? "Save project" : "Create project"}</button></div></form></div>}
      {configurationMove && <Dialog.Root open onOpenChange={(open) => !open && setConfigurationMove(null)}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="close-modal configuration-move-modal" aria-describedby="configuration-move-help"><Dialog.Title>Move {configurationMove.entry.name}?</Dialog.Title><Dialog.Description id="configuration-move-help">This changes the project configuration used for validation, forecasts, and future generations. Existing runs keep their captured inputs.</Dialog.Description><p>{snapshot?.projects.find((project) => project.id === configurationMove.entry.project_id)?.name || "Ungrouped"} → {snapshot?.projects.find((project) => project.id === configurationMove.projectId)?.name || "Ungrouped"}</p><div className="close-modal-actions"><Dialog.Close className="button-quiet">Cancel</Dialog.Close><button className="button-primary" onClick={() => void assignProject(configurationMove.entry, configurationMove.projectId, true)}>Move scenario</button></div></Dialog.Content></Dialog.Portal></Dialog.Root>}
      {deletingScenario && api && <DeleteScenarioDialog item={deletingScenario} api={api} onClose={() => setDeletingScenario(null)} onDeleted={async () => { if (selectedId === deletingScenario.id) { setSelectedId(null); setSelectedConversation(null); setWorkspaceTarget("overview"); } setDeletingScenario(null); await studio.reload(); showNotice("Scenario permanently deleted."); }} /> }
      {deletingPack && api && <DeletePackDialog item={deletingPack} api={api} onClose={() => setDeletingPack(null)} onDeleted={async () => { if (selectedId === deletingPack.id) { setSelectedId(null); setSelectedConversation(null); setWorkspaceTarget("overview"); } setDeletingPack(null); await studio.reload(); showNotice("Pack permanently deleted."); }} />}
      {deletingProject && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Delete project"><h2>Delete {deletingProject.name}?</h2><p>Its scenarios and packs will move to Ungrouped. Their source files, conversations, and runs will remain available.</p>{deletingProject.overlay_enabled && <p>Its shared configuration will stop applying to future work. Configuration files will be preserved.</p>}<div className="close-modal-actions"><button className="button-quiet" onClick={() => setDeletingProject(null)}>Cancel</button><button className="button-danger" disabled={busy} onClick={() => void deleteProject()}>Delete project</button></div></div></div>}
      {editingConversation && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Rename conversation" onSubmit={(event) => { event.preventDefault(); void renameConversation(); }}><h2>Rename conversation</h2><label className="modal-field">Name<input autoFocus aria-label="Conversation name" maxLength={80} value={editingTitle} onChange={(event) => setEditingTitle(event.target.value)} /></label><div className="close-modal-actions"><button type="button" className="button-quiet" onClick={() => setEditingConversation(null)}>Cancel</button><button type="submit" className="button-primary" disabled={!editingTitle.trim()}>Save name</button></div></form></div>}
      {deletingConversation && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Delete conversation"><h2>{deletingConversation.draft_kind ? "Delete draft?" : "Delete conversation?"}</h2><p><strong>{deletingConversation.title}</strong> will be removed from Studio. Its Codex thread and any authored files remain available.</p><div className="close-modal-actions"><button className="button-quiet" onClick={() => setDeletingConversation(null)}>Cancel</button><button className="button-danger" onClick={() => void deleteConversation()}>{deletingConversation.draft_kind ? "Delete draft" : "Delete conversation"}</button></div></div></div>}
      {closeProblem && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Close EvidenceForge Studio"><h2>{closeProblem.type === "waiting" ? "Waiting for checkpoints" : closeProblem.type === "confirm_delete" ? "Delete incomplete bundles?" : "These jobs cannot checkpoint"}</h2>{closeProblem.type === "checkpoint_disabled" && <><p>Choose what happens to each checkpoint-disabled generation before closing.</p>{closeProblem.jobIds.map((id) => <label className="close-choice" key={id}><span>{snapshot.jobs.find((job) => job.id === id)?.scenario || id}</span><select aria-label={`Close action for ${id}`} value={closeChoices[id] || ""} onChange={(event) => setCloseChoices({ ...closeChoices, [id]: event.target.value as "continue" | "stop" })}><option value="">Choose an action</option><option value="continue">Continue this job</option><option value="stop">Stop and preserve files</option></select></label>)}</>}{closeProblem.type === "confirm_delete" && <p>Incomplete app-created bundles will be removed after their jobs stop. Completed and imported bundles are kept.</p>}{closeProblem.type === "waiting" && <><p>{closeProblem.jobIds.length} active generations are reaching a safe checkpoint.</p>{closeProblem.failures?.map((failure) => <p className="error-text" key={failure.id}>{failure.detail}</p>)}</>}<div className="close-modal-actions"><button className="button-quiet" onClick={() => { if (closeProblem.type === "waiting") void api.request("/v1/session/cancel-close", "POST").catch((error) => setNotice(String(error))); setCloseProblem(null); }}>Cancel close</button>{closeProblem.type === "confirm_delete" && <button className="button-primary" onClick={() => void submitClose({ confirm_delete: true })}>Delete and close</button>}{closeProblem.type === "checkpoint_disabled" && <button className="button-primary" disabled={closeProblem.jobIds.some((id) => !closeChoices[id])} onClick={() => void submitClose({ generation_exceptions: closeChoices })}>Apply and close</button>}</div></div></div>}
    </main>
  </div></Tooltip.Provider>;
}

declare global { interface Window { __TAURI_INTERNALS__?: object } }
export default App;
