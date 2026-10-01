import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import App from "../src/App";
import { StudioApi, StudioApiError, StudioSnapshot } from "../src/api";
import { JobCard } from "../src/components";
import { BundleFileBrowser } from "../src/BundleFileBrowser";
import { chronologicalJobs } from "../src/jobOrder";
import { scenarioStates } from "../src/ScenarioStates";
import { useStudio } from "../src/useStudio";

const workspace = "/tmp/EvidenceForge";
const snapshot: StudioSnapshot = {
  seq: 12,
  settings: {
    workspace,
    recent_workspaces: [],
    output_parents: {},
    max_concurrent_generations: 2,
    checkpoint_hours: 24,
    quit: {
      action: "continue", continue_queued_generations: true,
      continue_evaluations: "continue", pause_close_timing: "handoff",
      pause_evaluations: "finish", kill_incomplete_bundles: "preserve",
      authoring_turns: "stop",
    },
    skill_install_scope: "global", skill_install_agent: "all",
    codex_path: null, eforge_path: null,
  },
  paths: { config: "/tmp/config", data: "/tmp/data", state: "/tmp/state", cache: "/tmp/cache", logs: "/tmp/logs" },
  codex_health: { state: "connected", detail: "Codex is responding" },
  projects: [],
  folders: [],
  views: [],
  items: [
    { id: "alpha", workspace, kind: "scenario", path: `${workspace}/scenarios/alpha/scenario.yaml`, name: "Alpha", description: "A first scenario", version: "2.0", modified_at: 1800000000, source_sha256: "sha-alpha", users: 3, systems: 4, events: 5, folder: null, project_id: null, hidden: false, imported: false },
    { id: "bravo", workspace, kind: "scenario", path: `${workspace}/scenarios/bravo/scenario.yaml`, name: "Bravo", description: "A second scenario", version: "2.0", modified_at: 1800000000, source_sha256: "sha-bravo", users: 2, systems: 2, events: 2, folder: null, project_id: null, hidden: false, imported: false },
  ],
  validations: {},
  conversations: [
    { id: "chat-1", workspace, item_id: "alpha", draft_kind: null, draft_path: null, draft_project_id: null, thread_id: "thread-1", title: "Initial design", model_id: null, reasoning_effort: null, active: false, needs_attention: false, connection_note: null, updated_at: 1800000000 },
    { id: "chat-2", workspace, item_id: "alpha", draft_kind: null, draft_path: null, draft_project_id: null, thread_id: "thread-2", title: "Revise timeline", model_id: null, reasoning_effort: null, active: false, needs_attention: false, connection_note: null, updated_at: 1799999900 },
  ],
  jobs: [
    { id: "job-1", kind: "generation", status: "running", status_message: "", scenario: `${workspace}/scenarios/alpha/scenario.yaml`, output_root: `${workspace}/runs/alpha/one`, progress: { phase: "Generating", completed_hours: 2, total_hours: 8, warmup_hours: 0, storyline_event: 0, storyline_total: 0, detail: "Hour 2" } },
    { id: "job-2", kind: "generation", status: "running", status_message: "", scenario: `${workspace}/scenarios/bravo/scenario.yaml`, output_root: `${workspace}/runs/bravo/two`, progress: { phase: "Generating", completed_hours: 6, total_hours: 8, warmup_hours: 0, storyline_event: 0, storyline_total: 0, detail: "Hour 6" } },
  ],
  imported_bundles: [],
};

vi.mock("../src/useStudio", () => ({
  useStudio: (() => {
    const api = { download: vi.fn(async () => ({ status: "browser" })), readTextPreview: vi.fn(async () => ({ text: "preview", truncated: false, binary: false })), request: vi.fn(async (path: string, method?: string, body?: unknown) => {
      if (path.endsWith("/history")) return { thread: { turns: [] } };
      if (path === "/v1/codex/pending") return [];
      if (path === "/v1/codex/status") return { available: true, models: { data: [] }, skills: { data: [] } };
      if (path === "/v1/packs/publisher") return { configured: false, publisher: null, publisher_display_name: null, scope: null };
      if (path === "/v1/jobs/bundle-sizes") return { "job-1": 1536, "completed-run": 2 * 1024 ** 2 };
      if (path === "/v1/jobs/evaluation-1/scorecard") return {
        scenario_name: "Alpha", evaluated_at: "2026-09-30T16:00:00Z",
        overall_score: 89.4, acceptance_passed: true, total_records: 12345,
        source_counts: { zeek_conn: 12345 },
        pillars: [{ name: "Parseability", score: 94, sub_scores: [{ name: "Schema", score: 94, details: "Valid fields", skipped: false }] }],
        acceptance_criteria: [{ name: "Schema gate", threshold: 80, actual: 94, passed: true, level: "hard" }],
        flags: [],
      };
      if (path === "/v1/settings" && method === "PUT") return body;
      return {};
    }) };
    const reload = vi.fn(async () => undefined);
    const subscribeEvents = () => () => undefined;
    return () => ({ api, snapshot, error: null, liveState: "connected", validations: {}, subscribeEvents, reload });
  })(),
}));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn(async () => undefined) }));
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => Boolean(window.__TAURI_INTERNALS__),
  invoke: vi.fn(async () => undefined),
}));
vi.mock("@tauri-apps/api/window", () => {
  const current = {
    closeHandler: null as null | ((event: { preventDefault: () => void }) => Promise<void>),
    destroy: vi.fn(async () => undefined),
    onCloseRequested: vi.fn(async (handler: (event: { preventDefault: () => void }) => Promise<void>) => {
      current.closeHandler = handler;
      return () => undefined;
    }),
  };
  return { getCurrentWindow: () => current };
});

afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); });

test("path controls copy the complete path even when the label is shortened", async () => {
  const writeText = vi.fn(async (_value: string) => undefined);
  const user = userEvent.setup();
  const clipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  try {
    const { container } = render(<App />);
    await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
    await user.click(screen.getByRole("button", { name: "Copy scenario path" }));
    expect(writeText).toHaveBeenCalledWith(snapshot.items[0].path);
    expect(screen.getByRole("button", { name: "Path copied" })).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: "Generation" }));
    await user.click(container.querySelector("#job-job-1 > summary")!);
    await user.click(screen.getByRole("button", { name: "Copy bundle path" }));
    expect(writeText).toHaveBeenCalledWith(snapshot.jobs[0].output_root);
  } finally {
    if (clipboard) Object.defineProperty(navigator, "clipboard", clipboard);
    else Reflect.deleteProperty(navigator, "clipboard");
  }
});

test("operation icons distinguish current, warning, and stale results", () => {
  const complete = {
    ...snapshot,
    validations: {
      alpha: { source_sha256: "sha-alpha", completed_at: 1800000000,
        result: { exit_code: 0, error: "", report: { severity_counts: { error: 0, warning: 2 } } } },
    },
    jobs: [
      { id: "gen", kind: "generation" as const, status: "completed", status_message: "", scenario: snapshot.items[0].path, source_sha256: "sha-alpha", output_root: "/tmp/run", started_at: 1800000001 },
      { id: "eval", kind: "evaluation" as const, status: "completed", status_message: "", generation_id: "gen", output_root: "/tmp/run", created_at: 1800000002 },
    ],
  };
  expect(scenarioStates(snapshot.items[0], complete).map((state) => state.state)).toEqual(["warning", "success", "success"]);
  expect(scenarioStates({ ...snapshot.items[0], source_sha256: "edited" }, complete).map((state) => state.state)).toEqual(["stale", "stale", "stale"]);
});

test("a saved evaluation scorecard stays visible on the scenario and run", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [
    { ...originalJobs[0], status: "completed" },
    { id: "evaluation-1", kind: "evaluation", status: "completed", status_message: "", generation_id: "job-1", output_root: originalJobs[0].output_root, created_at: 1800000050,
      scorecard: { overall_score: 89.4, acceptance_passed: true, total_records: 12345, evaluated_at: "2026-09-30T16:00:00Z" } },
  ];
  try {
    const { container } = render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
    expect(screen.getByText("89/100")).toBeTruthy();
    expect(screen.getByText("12,345 records")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "View scorecard" }));
    expect(screen.getByRole("tab", { name: "Scoring" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText(/89\/100 · Pass/)).toBeTruthy();
    await waitFor(() => expect(screen.getByRole("region", { name: "Saved scorecard" })).toBeTruthy());
    expect(container.querySelector("#job-evaluation-1")?.hasAttribute("open")).toBe(true);
    expect(screen.getByText("Parseability")).toBeTruthy();
    expect(screen.getByText("Schema gate")).toBeTruthy();
    await user.click(screen.getByText("Records by source"));
    expect(screen.getByText("zeek_conn")).toBeTruthy();
  } finally {
    snapshot.jobs = originalJobs;
  }
});

test("library cards keep operation icons beside the title without a redundant service label", () => {
  render(<App />);
  const card = screen.getByRole("button", { name: /AlphaA first scenario/ }).closest(".library-card");
  expect(card).not.toBeNull();
  expect(card?.querySelectorAll(".scenario-states.compact .state-icon")).toHaveLength(3);
  expect(card?.querySelector(".card-footer")).toBeNull();
  expect(within(card as HTMLElement).getByRole("button", { name: "Download bundle for Alpha" })).toBeTruthy();
  expect(screen.queryByText("Local service")).toBeNull();
});

test("a scenario can be cloned from its library menu with a new name", async () => {
  const user = userEvent.setup();
  const request = vi.mocked(useStudio().api!.request);
  const originalItems = snapshot.items;
  try {
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Options for Alpha" }));
    await user.click(screen.getByRole("menuitem", { name: "Clone scenario…" }));
    expect(screen.getByRole("dialog", { name: "Clone scenario" })).toBeTruthy();
    const clone = { ...snapshot.items[0], id: "alpha-copy", name: "Alpha-copy", path: `${workspace}/scenarios/Alpha-copy/scenario.yaml` };
    snapshot.items = [...originalItems, clone];
    request.mockResolvedValueOnce(clone);
    await user.clear(screen.getByRole("textbox", { name: "New scenario name" }));
    await user.type(screen.getByRole("textbox", { name: "New scenario name" }), "Alpha-copy");
    await user.click(screen.getByRole("button", { name: "Clone scenario" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/scenarios/alpha/clone", "POST", { name: "Alpha-copy" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Clone scenario" })).toBeNull());
    expect(screen.getByRole("heading", { name: "Alpha-copy" })).toBeTruthy();
  } finally {
    snapshot.items = originalItems;
  }
});

test("a pack clone requests a workspace publisher when one is not configured", async () => {
  const user = userEvent.setup();
  const request = vi.mocked(useStudio().api!.request);
  const originalItems = snapshot.items;
  const pack = {
    ...originalItems[0], id: "pack-1", kind: "industry_pack" as const,
    name: "finance", version: "1.0.0", path: `${workspace}/packs/industry/finance/pack.yaml`,
  };
  const clone = { ...pack, id: "pack-2", name: "finance-copy", path: `${workspace}/packs/industry/finance-copy/pack.yaml` };
  snapshot.items = [...originalItems, pack];
  try {
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Industry packs" }));
    await user.click(screen.getByRole("button", { name: "Options for finance" }));
    await user.click(screen.getByRole("menuitem", { name: "Clone pack…" }));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Publisher ID" })).toBeTruthy());
    expect(screen.getByRole("textbox", { name: "Pack version" })).toHaveProperty("value", "1.0.0");
    await user.type(screen.getByRole("textbox", { name: "Publisher ID" }), "local-team");
    await user.type(screen.getByRole("textbox", { name: "Publisher display name" }), "Local Team");
    snapshot.items = [...originalItems, pack, clone];
    request.mockResolvedValueOnce(clone);
    await user.click(screen.getByRole("button", { name: "Clone pack" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith(
      "/v1/packs/pack-1/clone", "POST",
      { name: "finance-copy", version: "1.0.0", publisher: "local-team", publisher_display_name: "Local Team" },
      190000,
    ));
    await waitFor(() => expect(screen.getByRole("heading", { name: "finance-copy" })).toBeTruthy());
  } finally {
    snapshot.items = originalItems;
  }
});

test("projects filter scenarios and accept card drops, with Ungrouped as a destination", async () => {
  const originalProjects = snapshot.projects;
  const originalItems = snapshot.items;
  snapshot.projects = [{ id: "project-1", workspace, name: "Casework", description: "Training cases", updated_at: 1 }];
  snapshot.items = [{ ...originalItems[0], project_id: "project-1" }, originalItems[1]];
  try {
    render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Open project Casework" }));
    expect(screen.getByText("Training cases")).toBeTruthy();
    expect(screen.getByText("Alpha", { selector: ".card-body strong" })).toBeTruthy();
    expect(screen.queryByText("Bravo", { selector: ".card-body strong" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "All scenarios" }));
    const bravo = screen.getByText("Bravo", { selector: ".card-body strong" }).closest(".library-card");
    const target = screen.getByRole("button", { name: "Open project Casework" }).closest(".project-nav-entry");
    const transfer = { effectAllowed: "", dropEffect: "", setData: vi.fn(), getData: vi.fn(() => "bravo") };
    fireEvent.dragStart(bravo?.querySelector(".card-drag-handle") as HTMLElement, { dataTransfer: transfer });
    expect(transfer.setData).toHaveBeenCalledWith("application/x-evidenceforge-scenario", "bravo");
    fireEvent.dragOver(target as HTMLElement, { dataTransfer: transfer });
    expect(target?.classList.contains("drop-target")).toBe(true);
    fireEvent.drop(target as HTMLElement, { dataTransfer: transfer });
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/items/bravo", "PATCH", { project_id: "project-1" },
    ));

    const alpha = screen.getByText("Alpha", { selector: ".card-body strong" }).closest(".library-card");
    transfer.getData = vi.fn(() => "alpha");
    fireEvent.dragStart(alpha?.querySelector(".card-drag-handle") as HTMLElement, { dataTransfer: transfer });
    fireEvent.dragOver(screen.getByRole("button", { name: "Ungrouped" }), { dataTransfer: transfer });
    fireEvent.drop(screen.getByRole("button", { name: "Ungrouped" }), { dataTransfer: transfer });
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/items/alpha", "PATCH", { project_id: null },
    ));
  } finally {
    snapshot.projects = originalProjects;
    snapshot.items = originalItems;
  }
});

test("project creation is available in the project rail", async () => {
  render(<App />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "New project" }));
  const dialog = screen.getByRole("dialog", { name: "New project" });
  await user.type(within(dialog).getByRole("textbox", { name: "Project Name" }), "FOR668");
  await user.type(within(dialog).getByRole("textbox", { name: "Project description" }), "Autumn exercise");
  vi.mocked(useStudio().api!.request).mockResolvedValueOnce({ id: "new-project", workspace, name: "FOR668", description: "Autumn exercise", updated_at: 1 });
  await user.click(within(dialog).getByRole("button", { name: "Create project" }));
  await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/projects", "POST", { name: "FOR668", description: "Autumn exercise" },
  ));
});

test("library search includes indexed scenario YAML content", async () => {
  vi.mocked(useStudio().api!.request).mockResolvedValueOnce([snapshot.items[1]]);
  render(<App />);
  await userEvent.setup().type(screen.getByRole("textbox", { name: "Search scenarios" }), "yaml:rare-host");
  await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/items?kind=scenario&search=yaml%3Arare-host",
  ));
  await waitFor(() => expect(screen.getByText("Bravo", { selector: ".card-body strong" })).toBeTruthy());
  expect(screen.queryByText("Alpha", { selector: ".card-body strong" })).toBeNull();
});

test("hidden items can be revealed and unhidden from the library", async () => {
  const originalItems = snapshot.items;
  snapshot.items = [originalItems[0], { ...originalItems[1], hidden: true }];
  try {
    render(<App />);
    const user = userEvent.setup();
    expect(screen.queryByText("Bravo", { selector: ".card-body strong" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Show hidden items" }));
    expect(screen.getByText("Bravo", { selector: ".card-body strong" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Options for Bravo" }));
    await user.click(screen.getByRole("menuitem", { name: "Unhide" }));
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/items/bravo", "PATCH", { hidden: false },
    ));
  } finally {
    snapshot.items = originalItems;
  }
});

test("saved views store and restore library search and filters", async () => {
  const originalViews = snapshot.views;
  const originalItems = snapshot.items;
  snapshot.items = [originalItems[0], { ...originalItems[1], hidden: true }];
  snapshot.views = [{ name: "Ungrouped review", kind: "scenario", search: "Alpha", folder: null,
    project_id: null, ungrouped: true, show_hidden: true }];
  try {
    render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Saved views" }));
    const dialog = screen.getByRole("dialog", { name: "Saved views" });
    await user.click(within(dialog).getByRole("button", { name: "Apply saved view Ungrouped review" }));
    expect((screen.getByRole("textbox", { name: "Search scenarios" }) as HTMLInputElement).value).toBe("Alpha");
    expect(screen.getByRole("button", { name: "Hide hidden items" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ungrouped" }).className).toContain("active");
    await user.click(screen.getByRole("button", { name: "Saved views" }));
    const reopened = screen.getByRole("dialog", { name: "Saved views" });
    await user.type(within(reopened).getByRole("textbox", { name: "Saved view name" }), "Review set");
    await user.click(within(reopened).getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/views", "POST", { name: "Review set", kind: "scenario", search: "Alpha", folder: null,
        project_id: null, ungrouped: true, show_hidden: true },
    ));
    await user.click(within(reopened).getByRole("button", { name: "Delete saved view Ungrouped review" }));
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/views/Ungrouped%20review", "DELETE",
    ));
  } finally {
    snapshot.views = originalViews;
    snapshot.items = originalItems;
  }
});

test("pack folders remain available while scenario folders are removed", async () => {
  const originalFolders = snapshot.folders;
  const originalItems = snapshot.items;
  snapshot.folders = ["Training"];
  snapshot.items = [{ ...originalItems[0], kind: "industry_pack", folder: "Training" }, { ...originalItems[1], kind: "industry_pack" }];
  try {
    render(<App />);
    const user = userEvent.setup();
    expect(screen.queryByRole("button", { name: "Filter by folder" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Industry packs" }));
    await user.click(screen.getByRole("button", { name: "Filter by folder" }));
    await user.click(screen.getByRole("menuitem", { name: "Training" }));
    expect(screen.getByText("Alpha", { selector: ".card-body strong" })).toBeTruthy();
    expect(screen.queryByText("Bravo", { selector: ".card-body strong" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Saved views" }));
    const dialog = screen.getByRole("dialog", { name: "Saved views" });
    await user.type(within(dialog).getByRole("textbox", { name: "Saved view name" }), "Training items");
    await user.click(within(dialog).getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/views", "POST", { name: "Training items", kind: "industry_pack", search: "", folder: "Training",
        project_id: null, ungrouped: false, show_hidden: false },
    ));
  } finally {
    snapshot.folders = originalFolders;
    snapshot.items = originalItems;
  }
});

test("a new virtual folder can be created from the library filter", async () => {
  render(<App />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Industry packs" }));
  await user.click(screen.getByRole("button", { name: "Filter by folder" }));
  await user.click(screen.getByRole("menuitem", { name: "New folder…" }));
  const dialog = screen.getByRole("dialog", { name: "New folder" });
  await user.type(within(dialog).getByRole("textbox", { name: "Folder Name" }), "Response work");
  vi.mocked(useStudio().api!.request).mockResolvedValueOnce({ name: "Response work" });
  await user.click(within(dialog).getByRole("button", { name: "Create folder" }));
  await waitFor(() => expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/folders", "POST", { name: "Response work" },
  ));
});

test("command menu opens with the keyboard and navigates to a scenario", async () => {
  render(<App />);
  const user = userEvent.setup();
  await user.keyboard("{Control>}k{/Control}");
  const dialog = screen.getByRole("dialog", { name: "Command menu" });
  await user.type(within(dialog).getByRole("textbox", { name: "Search commands" }), "Bravo{Enter}");
  expect(screen.queryByRole("dialog", { name: "Command menu" })).toBeNull();
  expect(screen.getByRole("heading", { name: "Bravo" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Open command menu" }));
  expect(screen.getByRole("dialog", { name: "Command menu" })).toBeTruthy();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog", { name: "Command menu" })).toBeNull();
});

test("new scenario opens a persistent draft conversation that can be resumed", async () => {
  const originalConversations = snapshot.conversations;
  const originalItems = snapshot.items;
  const draft = {
    id: "draft-1", workspace, item_id: null, draft_kind: "scenario" as const,
    draft_path: `${workspace}/scenarios/studio-draft-1/scenario.yaml`,
    draft_project_id: null, draft_name: "Short-scenario", thread_id: null, title: "New conversation", model_id: null,
    reasoning_effort: null, active: false, needs_attention: false, connection_note: null,
    updated_at: 1800000100,
  };
  try {
    vi.mocked(useStudio().api!.request).mockImplementationOnce(async () => {
      snapshot.conversations = [draft, ...originalConversations];
      return draft;
    });
    const view = render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "New scenario" }));
    await user.type(screen.getByRole("textbox", { name: "Scenario Name" }), "Short-scenario");
    await user.click(screen.getByRole("button", { name: "Create scenario" }));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Message to Codex" })).toBeTruthy());
    expect(screen.getByText("Create a scenario")).toBeTruthy();
    expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/conversations", "POST", { draft_kind: "scenario", project_id: null, name: "Short-scenario" },
    );
    await user.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Scenarios" }));
    expect(screen.getByRole("button", { name: /^Short-scenario/ })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /^Short-scenario/ }));
    expect(screen.getByRole("textbox", { name: "Message to Codex" })).toBeTruthy();
    snapshot.items = [...originalItems, { ...originalItems[0], id: "authored-1", path: draft.draft_path, name: "New authored" }];
    snapshot.conversations = [{ ...draft, item_id: "authored-1", draft_kind: null, draft_project_id: null }, ...originalConversations];
    view.rerender(<App />);
    await waitFor(() => expect(screen.getByRole("tab", { name: /Conversations/ })).toBeTruthy());
    expect(screen.getByText("New authored", { selector: ".topbar-title strong" })).toBeTruthy();
  } finally {
    snapshot.conversations = originalConversations;
    snapshot.items = originalItems;
  }
});

test("scenario names show live errors and block invalid creation", async () => {
  render(<App />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "New scenario" }));
  const input = screen.getByRole("textbox", { name: "Scenario Name" });
  const create = screen.getByRole("button", { name: "Create scenario" });
  expect(create.hasAttribute("disabled")).toBe(true);
  await user.type(input, "A scenario!");
  expect(input.getAttribute("aria-invalid")).toBe("true");
  expect(screen.getByText("Use letters, numbers, hyphens, or underscores; no spaces.")).toBeTruthy();
  expect(create.hasAttribute("disabled")).toBe(true);
  await user.clear(input);
  await user.type(input, "A-scenario_2");
  expect(input.getAttribute("aria-invalid")).toBe("false");
  expect(screen.queryByText("Use letters, numbers, hyphens, or underscores; no spaces.")).toBeNull();
  expect(create.hasAttribute("disabled")).toBe(false);
});

test("scenario workspace has generation setup and a run-specific scoring action", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [{ ...originalJobs[0], status: "completed", started_at: 1800000010 }, originalJobs[1],
    { ...originalJobs[0], id: "older-alpha", status: "completed", started_at: 1800000000 }];
  try {
    render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
    await user.click(screen.getByRole("button", { name: "Generate", exact: true }));
    expect(screen.getByRole("tab", { name: "Generation" }).getAttribute("aria-selected")).toBe("true");
    const setup = screen.getByRole("heading", { name: "Generate this scenario" }).closest("section")!;
    await user.clear(screen.getByRole("textbox", { name: "Output parent folder" }));
    await user.type(screen.getByRole("textbox", { name: "Output parent folder" }), "/tmp/other-runs");
    await user.click(within(setup).getByRole("button", { name: "Generate" }));
    expect(useStudio().api!.request).toHaveBeenCalledWith("/v1/jobs/generations", "POST", { scenario_id: "alpha", output_parent: "/tmp/other-runs" });
    await user.click(screen.getByRole("tab", { name: "Scoring" }));
    expect(screen.getByRole("combobox", { name: "Generated run to evaluate" })).toBeTruthy();
    expect((screen.getByRole("combobox", { name: "Generated run to evaluate" }) as HTMLSelectElement).value).toBe("job-1");
    await user.selectOptions(screen.getByRole("combobox", { name: "Generated run to evaluate" }), "older-alpha");
    await user.click(screen.getByRole("button", { name: "Evaluate" }));
    expect(useStudio().api!.request).toHaveBeenCalledWith("/v1/jobs/evaluations", "POST", { generation_id: "older-alpha" });
    expect(screen.queryByText("Bravo")).toBeNull();
  } finally { snapshot.jobs = originalJobs; }
});

test("scoring source links navigate back to the exact generation tab and row", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [{ ...originalJobs[0], status: "completed" }, {
    id: "evaluation-1", kind: "evaluation", status: "completed", status_message: "",
    generation_id: "job-1", output_root: originalJobs[0].output_root,
  }];
  try {
    const { container } = render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
    await user.click(screen.getByRole("tab", { name: "Scoring" }));
    await user.click(screen.getByRole("button", { name: "Jump to generation #job-1" }));
    expect(screen.getByRole("tab", { name: "Generation" }).getAttribute("aria-selected")).toBe("true");
    expect(container.querySelector("#job-job-1")?.hasAttribute("open")).toBe(true);
    await user.click(screen.getByRole("tab", { name: "Scoring" }));
    expect(screen.getByRole("tab", { name: "Scoring" }).getAttribute("aria-selected")).toBe("true");
  } finally { snapshot.jobs = originalJobs; }
});

test("Codex status dot explains a stalled connection and reconnects with active-turn warning", async () => {
  const user = userEvent.setup();
  const originalHealth = snapshot.codex_health;
  const originalConversations = snapshot.conversations;
  snapshot.codex_health = { state: "stalled", detail: "Codex did not answer a health probe" };
  snapshot.conversations = [{ ...originalConversations[0], active: true }, originalConversations[1]];
  try {
    render(<App />);
    const dot = screen.getByRole("button", { name: /Codex stalled: Codex did not answer/ });
    expect(dot.querySelector(".codex-indicator-dot")).toBeTruthy();
    await user.hover(dot);
    expect(await screen.findByText("Codex did not answer a health probe")).toBeTruthy();
    await user.click(dot);
    const dialog = screen.getByRole("dialog", { name: "Reconnect Codex" });
    expect(within(dialog).getByText(/interrupt 1 active turn/)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: "Reconnect" }));
    expect(useStudio().api?.request).toHaveBeenCalledWith(
      "/v1/codex/reconnect", "POST", { interrupt_active: true }, 30000,
    );
  } finally {
    snapshot.codex_health = originalHealth;
    snapshot.conversations = originalConversations;
  }
});

test("validation findings open a new chat with a reviewable repair draft", async () => {
  const user = userEvent.setup();
  const originalValidations = snapshot.validations;
  const originalConversations = snapshot.conversations;
  const created = { ...originalConversations[0], id: "chat-fix", thread_id: null, title: "New conversation" };
  snapshot.validations = {
    alpha: { source_sha256: "sha-alpha", completed_at: 1800000000,
      result: { exit_code: 1, error: "", report: {
        valid: false, scenario: { name: "Alpha" }, issues: [
          { severity: "error", field_path: "environment.users.0", message: "Unknown host", suggestion: "Choose a declared host" },
        ],
      } } },
  };
  snapshot.conversations = [...originalConversations, created];
  const request = vi.mocked(useStudio().api!.request);
  request.mockResolvedValueOnce(created);
  try {
    render(<App />);
    await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
    await user.click(screen.getByRole("tab", { name: "Validation" }));
    await user.click(screen.getByRole("button", { name: "Fix in chat" }));
    expect(request).toHaveBeenCalledWith("/v1/conversations", "POST", { item_id: "alpha" });
    const draft = screen.getByRole("textbox", { name: "Message to Codex" }) as HTMLTextAreaElement;
    await waitFor(() => expect(draft.value).toContain("Unknown host"));
    expect(draft.value).toContain("environment.users.0");
    expect(draft.value).toContain("First rerun eforge validate");
    expect(request.mock.calls.some(([path]) => String(path).endsWith("/turns"))).toBe(false);
    await user.type(draft, "{enter}");
    await waitFor(() => expect(request).toHaveBeenCalledWith(
      "/v1/conversations/chat-fix/turns", "POST", expect.objectContaining({ text: expect.stringContaining("Unknown host") }),
    ));
    await user.click(screen.getByRole("tab", { name: "Overview" }));
    await user.click(screen.getByRole("tab", { name: /Conversations/ }));
    expect((screen.getByRole("textbox", { name: "Message to Codex" }) as HTMLTextAreaElement).value).toBe("");
  } finally {
    snapshot.validations = originalValidations;
    snapshot.conversations = originalConversations;
  }
});

test("job center counts working chats separately from chats awaiting input", async () => {
  const user = userEvent.setup();
  const original = snapshot.conversations;
  snapshot.conversations = [
    { ...original[0], active: true, needs_attention: false },
    { ...original[1], active: true, needs_attention: true },
  ];
  try {
    render(<App />);
    await user.click(screen.getByRole("button", { name: /Job center/ }));
    expect(screen.getByLabelText("1 active chats")).toBeTruthy();
    expect(screen.getByLabelText("1 chats need input")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Initial design.*Alpha.*Working/ }));
    expect(screen.getByRole("tab", { name: /Conversations/ }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("button", { name: "Open Initial design" })).toBeTruthy();
  } finally {
    snapshot.conversations = original;
  }
});

test("scenario workspace opens the correct persistent conversations", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
  await user.click(screen.getByRole("tab", { name: /Conversations/ }));
  expect(screen.getAllByText("Initial design").length).toBeGreaterThan(0);
  await user.click(screen.getByRole("button", { name: "Open Revise timeline" }));
  expect(within(screen.getByRole("main")).getAllByText("Revise timeline").length).toBeGreaterThan(0);
  expect(screen.getByText("Alpha", { selector: ".chat-topline span" })).toBeTruthy();
});

test("conversation menu exposes rename and delete actions", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
  await user.click(screen.getByRole("tab", { name: /Conversations/ }));
  await user.click(screen.getByRole("button", { name: "Options for Initial design" }));
  await user.click(screen.getByRole("menuitem", { name: "Rename" }));
  const name = screen.getByRole("textbox", { name: "Conversation name" });
  await user.clear(name);
  await user.type(name, "Credential timeline");
  await user.click(screen.getByRole("button", { name: "Save name" }));
  expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/conversations/chat-1", "PATCH", { title: "Credential timeline" },
  );
  await user.click(screen.getByRole("button", { name: "Options for Initial design" }));
  await user.click(screen.getByRole("menuitem", { name: "Delete" }));
  await user.click(screen.getByRole("button", { name: "Delete conversation" }));
  expect(useStudio().api?.request).toHaveBeenCalledWith("/v1/conversations/chat-1", "DELETE");
});

test("bundle picker downloads the selected completed run", async () => {
  const user = userEvent.setup();
  const original = snapshot.jobs;
  snapshot.jobs = [
    ...original,
    { id: "run-1", kind: "generation", status: "completed", status_message: "", scenario: snapshot.items[0].path, source_sha256: "sha-alpha", output_root: "/tmp/run-one", started_at: 1800000001 },
    { id: "run-2", kind: "generation", status: "completed", status_message: "", scenario: snapshot.items[0].path, source_sha256: "sha-alpha", output_root: "/tmp/run-two", started_at: 1800000002 },
  ];
  try {
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Download bundle for Alpha" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Run to download" }), "run-1");
    await user.click(screen.getByRole("button", { name: "Download ZIP" }));
    await waitFor(() => expect(useStudio().api?.download).toHaveBeenCalledWith(
      "/v1/items/alpha/bundles/run-1.zip", "Alpha-run-1.zip", expect.any(Function),
    ));
  } finally {
    snapshot.jobs = original;
  }
});

test("generation capacity and checkpoint interval are editable in Jobs settings", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: "Settings" }));
  await user.click(screen.getByRole("button", { name: "Jobs" }));
  const save = screen.getByRole("button", { name: "Save settings" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  const capacity = screen.getByRole("spinbutton", { name: "Concurrent generations" });
  await user.clear(capacity);
  await user.type(capacity, "3");
  const checkpoints = screen.getByRole("spinbutton", { name: "Hours between checkpoints" });
  await user.clear(checkpoints);
  await user.type(checkpoints, "6");
  expect(save.disabled).toBe(false);
  await user.click(save);
  expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/settings", "PUT", expect.objectContaining({ max_concurrent_generations: 3, checkpoint_hours: 6 }),
  );
  await waitFor(() => expect(save.disabled).toBe(true));
  expect(screen.getByRole("status").textContent).toBe("Settings saved");
});

test("browser preview explains native folder actions without a Tauri invoke error", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: "Settings" }));
  await user.click(screen.getByRole("button", { name: "Open workspace folder" }));
  expect(screen.getByText(/Folder opening is available in the native app/)).toBeTruthy();
});

test("stopped run can regenerate, preview files, and confirm deletion", async () => {
  const user = userEvent.setup();
  const request = vi.fn(async (path: string) => path.endsWith("/files")
    ? { root: "/tmp/partial", files: [{ path: "partial.log", size: 42 }], truncated: false }
    : {});
  const download = vi.fn(async () => undefined);
  const readTextPreview = vi.fn(async () => ({ text: "partial output", truncated: false, binary: false }));
  const onChanged = vi.fn(async () => undefined);
  const job = { ...snapshot.jobs[0], status: "stopped", can_resume: false, output_root: "/tmp/partial" };
  const { container } = render(<JobCard job={job} api={{ request, download, readTextPreview } as unknown as StudioApi} onError={vi.fn()} onChanged={onChanged} />);
  await user.click(container.querySelector("summary")!);
  await user.click(screen.getByRole("button", { name: "View files" }));
  expect(screen.getByRole("dialog", { name: "Bundle files" })).toBeTruthy();
  await waitFor(() => expect(screen.getByText("partial output")).toBeTruthy());
  await user.click(screen.getByRole("button", { name: /partial.log/ }));
  expect(readTextPreview).toHaveBeenCalledWith(`/v1/jobs/${job.id}/files/partial.log`);
  await user.click(screen.getByRole("button", { name: "Download file" }));
  expect(download).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Close bundle files" }));
  await user.click(screen.getByRole("button", { name: "Regenerate" }));
  expect(request).toHaveBeenCalledWith(`/v1/jobs/${job.id}/regenerate`, "POST");
  await user.click(screen.getByRole("button", { name: "Delete bundle" }));
  const dialog = screen.getByRole("dialog", { name: "Delete bundle" });
  expect(dialog).toBeTruthy();
  await user.click(within(dialog).getByRole("button", { name: "Delete bundle" }));
  expect(request).toHaveBeenCalledWith(`/v1/jobs/${job.id}/incomplete-bundle`, "DELETE");
  expect(onChanged).toHaveBeenCalledTimes(2);
});

test("completed run exposes ZIP export and removes its bundle after confirmation", async () => {
  const user = userEvent.setup();
  const request = vi.fn(async () => ({}));
  const downloadBundle = vi.fn(async () => undefined);
  const onChanged = vi.fn(async () => undefined);
  const job = { ...snapshot.jobs[0], status: "completed", output_root: "/tmp/complete" };
  const { container } = render(<JobCard job={job} name="Alpha" api={{ request, downloadBundle } as unknown as StudioApi} onError={vi.fn()} onChanged={onChanged} />);
  await user.click(container.querySelector("summary")!);
  await user.click(screen.getByRole("button", { name: "Download ZIP" }));
  expect(downloadBundle).toHaveBeenCalledWith(job.id, "Alpha-job-1.zip", expect.any(Function));
  await user.click(screen.getByRole("button", { name: "Delete bundle" }));
  await user.click(within(screen.getByRole("dialog", { name: "Delete bundle" })).getByRole("button", { name: "Delete bundle" }));
  expect(request).toHaveBeenCalledWith(`/v1/jobs/${job.id}/bundle`, "DELETE");
  expect(onChanged).toHaveBeenCalledTimes(1);
});

test("job center renders independent progress bars for simultaneous generations", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: /Job center/ }));
  const bars = screen.getAllByRole("progressbar");
  expect(bars).toHaveLength(2);
  expect(bars.map((bar) => bar.getAttribute("aria-valuenow"))).toEqual(["25", "75"]);
});

test("job rows stay in submission order and sections can collapse", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [
    { ...originalJobs[1], submitted_at: 20, started_at: 20 },
    { ...originalJobs[0], submitted_at: 10, started_at: 50 },
    { id: "eval-1", kind: "evaluation", status: "completed", status_message: "", generation_id: "job-1", output_root: originalJobs[0].output_root, created_at: 30 },
  ];
  try {
    const { container } = render(<App />);
    await userEvent.setup().click(screen.getByRole("button", { name: /Job center/ }));
    expect([...container.querySelectorAll(".job-group")].map((entry) => entry.querySelector("summary strong")?.textContent)).toEqual(["Generations", "Evaluations"]);
    expect([...container.querySelectorAll(".job-group:first-child .job-row-name strong")].map((entry) => entry.textContent)).toEqual(["Alpha", "Bravo"]);
    const generations = container.querySelector(".job-group") as HTMLDetailsElement;
    await userEvent.setup().click(generations.querySelector("summary")!);
    expect(generations.open).toBe(false);
    await userEvent.setup().click(container.querySelector("#job-eval-1 > summary")!);
    await userEvent.setup().click(screen.getByRole("button", { name: "Jump to generation #job-1" }));
    expect(generations.open).toBe(true);
    expect((container.querySelector("#job-job-1") as HTMLDetailsElement).open).toBe(true);
    expect(container.querySelector("#job-job-1")?.classList.contains("source-highlight")).toBe(true);
    expect(document.activeElement).toBe(container.querySelector("#job-job-1 > summary"));
  } finally {
    snapshot.jobs = originalJobs;
  }
});

test("legacy resumed jobs use their bundle creation time for stable order", () => {
  const first = { ...snapshot.jobs[0], id: "first", output_root: `${workspace}/runs/alpha/20260930-120000-1234abcd`, started_at: 1000 };
  const second = { ...snapshot.jobs[1], id: "second", output_root: `${workspace}/runs/bravo/20260930-130000-5678abcd`, started_at: 200 };
  expect(chronologicalJobs([second, first]).map((job) => job.id)).toEqual(["first", "second"]);
});

test("bundle library groups runs by scenario and filters their status", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [
    originalJobs[1],
    { ...originalJobs[0], id: "completed-run", status: "completed", submitted_at: 1 },
    originalJobs[0],
  ];
  try {
    const { container } = render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Bundles" }));
    expect(screen.getByRole("heading", { name: "Bundles" })).toBeTruthy();
    expect([...container.querySelectorAll(".bundle-group > summary strong")].map((entry) => entry.textContent)).toEqual(["Alpha", "Bravo"]);
    await user.selectOptions(screen.getByRole("combobox", { name: "Filter bundles by status" }), "complete");
    expect(container.querySelectorAll(".bundle-group")).toHaveLength(1);
    expect(screen.getByText("Run #complete")).toBeTruthy();
    expect(screen.getByText("2.0 MB", { selector: ".bundle-size" })).toBeTruthy();
    await user.type(screen.getByRole("textbox", { name: "Search bundles" }), "not-here");
    expect(screen.getByText("No matching bundles")).toBeTruthy();
  } finally {
    snapshot.jobs = originalJobs;
  }
});

test("imported bundles appear beside Studio runs with read-only management", async () => {
  const original = snapshot.imported_bundles;
  snapshot.imported_bundles = [{
    id: "external-1", workspace, root: "/tmp/cli-output", scenario_name: "Alpha",
    created_at: 1800000001, size_bytes: 3145728, manifest_sha256: "abc",
  }];
  try {
    const user = userEvent.setup();
    const request = vi.mocked(useStudio().api!.request);
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Bundles" }));
    expect(screen.getByText("cli-output")).toBeTruthy();
    expect(screen.getByText("3.0 MB", { selector: ".bundle-size" })).toBeTruthy();
    await user.click(screen.getByText("cli-output"));
    expect(screen.getByText(/Studio did not create this bundle/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Remove from Studio" }));
    const dialog = screen.getByRole("dialog", { name: "Remove imported bundle" });
    await user.click(within(dialog).getByRole("button", { name: "Remove from Studio" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/bundles/external-1", "DELETE"));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Remove imported bundle" })).toBeNull());
  } finally {
    snapshot.imported_bundles = original;
  }
});

test("bundle import accepts a folder and discovery checks workspace runs", async () => {
  const user = userEvent.setup();
  const request = vi.mocked(useStudio().api!.request);
  render(<App />);
  await user.click(screen.getByRole("button", { name: "Bundles" }));
  await user.click(screen.getByRole("button", { name: "Import bundle" }));
  await user.type(screen.getByRole("textbox", { name: "Bundle folder" }), "/tmp/cli-output");
  await user.click(within(screen.getByRole("dialog", { name: "Import bundle" })).getByRole("button", { name: "Import bundle" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/bundles/import", "POST", { path: "/tmp/cli-output" }));
  await user.click(screen.getByRole("button", { name: "Find in workspace" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/bundles/discover", "POST"));
});

test("bundle viewer highlights YAML and downloads only when requested", async () => {
  const readTextPreview = vi.fn(async () => ({ text: "name: example\nenabled: true\n", truncated: false, binary: false }));
  const download = vi.fn(async () => undefined);
  render(<BundleFileBrowser jobId="job-1" files={{ root: "/tmp/run", files: [{ path: "RESOLVED_SCENARIO.yaml", size: 28 }], truncated: false }} api={{ readTextPreview, download } as unknown as StudioApi} onClose={vi.fn()} onError={vi.fn()} />);
  await waitFor(() => expect(screen.getByText("name:", { selector: ".syntax-key" })).toBeTruthy());
  expect(download).not.toHaveBeenCalled();
  await userEvent.setup().click(screen.getByRole("button", { name: "Download file" }));
  expect(download).toHaveBeenCalledWith("/v1/jobs/job-1/files/RESOLVED_SCENARIO.yaml", "RESOLVED_SCENARIO.yaml", expect.any(Function));
});

test("imported bundle viewer reads and saves files through its own route", async () => {
  const readTextPreview = vi.fn(async () => ({ text: "name: external\n", truncated: false, binary: false }));
  const download = vi.fn(async () => ({ status: "browser" }));
  render(<BundleFileBrowser jobId="external-1" kind="bundles" files={{ root: "/tmp/cli-output", files: [{ path: "RESOLVED_SCENARIO.yaml", size: 15 }], truncated: false }} api={{ readTextPreview, download } as unknown as StudioApi} onClose={vi.fn()} onError={vi.fn()} />);
  await waitFor(() => expect(readTextPreview).toHaveBeenCalledWith("/v1/bundles/external-1/files/RESOLVED_SCENARIO.yaml"));
  await userEvent.setup().click(screen.getByRole("button", { name: "Download file" }));
  expect(download).toHaveBeenCalledWith("/v1/bundles/external-1/files/RESOLVED_SCENARIO.yaml", "RESOLVED_SCENARIO.yaml", expect.any(Function));
});

test("bundle viewer opens ground truth before a manifest when both exist", async () => {
  const readTextPreview = vi.fn(async () => ({ text: "# Ground truth\n", truncated: false, binary: false }));
  render(<BundleFileBrowser jobId="job-1" files={{ root: "/tmp/run", files: [
    { path: "GENERATION_MANIFEST.json", size: 40 },
    { path: "GROUND_TRUTH.md", size: 15 },
  ], truncated: false }} api={{ readTextPreview } as unknown as StudioApi} onClose={vi.fn()} onError={vi.fn()} />);
  await waitFor(() => expect(readTextPreview).toHaveBeenCalledWith("/v1/jobs/job-1/files/GROUND_TRUTH.md"));
});

test("generation and evaluation cards use the authored scenario name", async () => {
  const originalJobs = snapshot.jobs;
  const originalItems = snapshot.items;
  const authored = {
    ...originalItems[0], id: "new-scenario", name: "LumenForge beacon",
    path: `${workspace}/scenarios/studio-22910ea064fd4ae2a0991b36aca924fc/scenario.yaml`,
  };
  snapshot.items = [...originalItems, authored];
  snapshot.jobs = [
    { ...originalJobs[0], id: "new-run", scenario: authored.path },
    { id: "new-evaluation", kind: "evaluation", status: "completed", status_message: "", generation_id: "new-run", output_root: "/tmp/run", created_at: 1800000050 },
  ];
  try {
    render(<App />);
    await userEvent.setup().click(screen.getByRole("button", { name: /Job center/ }));
    expect(screen.getAllByText("LumenForge beacon", { selector: ".job-row-name strong" })).toHaveLength(2);
    expect(screen.getByRole("progressbar", { name: "LumenForge beacon generation progress" })).toBeTruthy();
  } finally {
    snapshot.jobs = originalJobs;
    snapshot.items = originalItems;
  }
});

test("paused and queued runs keep their saved progress and show their actual state", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [
    { ...originalJobs[0], status: "paused", can_resume: true, progress: { ...originalJobs[0].progress!, completed_hours: 4, total_hours: 8 } },
    { ...originalJobs[1], status: "queued", progress: { ...originalJobs[1].progress!, completed_hours: 3, total_hours: 8 } },
  ];
  try {
    render(<App />);
    await userEvent.setup().click(screen.getByRole("button", { name: /Job center/ }));
    expect(screen.getAllByRole("progressbar").map((bar) => bar.getAttribute("aria-valuenow"))).toEqual(["50", "38"]);
    expect(screen.getAllByText(/Paused/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Queued to resume/)).toBeTruthy();
  } finally {
    snapshot.jobs = originalJobs;
  }
});

test("a stopped run without a checkpoint preserves its bar and cannot be resumed", async () => {
  const originalJobs = snapshot.jobs;
  snapshot.jobs = [{ ...originalJobs[0], status: "stopped", can_resume: false }];
  try {
    render(<App />);
    await userEvent.setup().click(screen.getByRole("button", { name: /Job center/ }));
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("25");
    expect(screen.getByText("No checkpoint to resume")).toBeTruthy();
    expect(screen.getByText(/Generation stopped before completion/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Resume" })).toBeNull();
  } finally {
    snapshot.jobs = originalJobs;
  }
});

test("Enter submits a turn while Shift+Enter inserts a newline", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole("button", { name: /AlphaA first scenario/ }));
  await user.click(screen.getByRole("tab", { name: /Conversations/ }));
  const input = screen.getByRole("textbox", { name: "Message to Codex" });
  await user.type(input, "check{shift>}{enter}{/shift}this{enter}");
  const client = useStudio().api;
  await waitFor(() => expect(client?.request).toHaveBeenCalledWith(
    "/v1/conversations/chat-1/turns", "POST", { text: "check\nthis", skill_name: null },
  ));
});

test("the close button hands off quit actions and exits the native window", async () => {
  Object.assign(window, { __TAURI_INTERNALS__: {} });
  render(<App />);
  const current = getCurrentWindow() as unknown as {
    closeHandler: ((event: { preventDefault: () => void }) => Promise<void>) | null;
  };
  await waitFor(() => expect(current.closeHandler).not.toBeNull());
  const preventDefault = vi.fn();
  await current.closeHandler?.({ preventDefault });
  expect(preventDefault).toHaveBeenCalled();
  expect(useStudio().api?.request).toHaveBeenCalledWith(
    "/v1/session/close", "POST", undefined, 3000,
  );
  expect(invoke).toHaveBeenCalledWith("studio_exit");
  delete window.__TAURI_INTERNALS__;
});

test("closing with a checkpoint-disabled run requires an explicit per-job choice", async () => {
  Object.assign(window, { __TAURI_INTERNALS__: {} });
  render(<App />);
  const current = getCurrentWindow() as unknown as {
    closeHandler: ((event: { preventDefault: () => void }) => Promise<void>) | null;
  };
  await waitFor(() => expect(current.closeHandler).not.toBeNull());
  const request = vi.mocked(useStudio().api!.request);
  request.mockRejectedValueOnce(new StudioApiError(409, {
    reason: "checkpoint_disabled", job_ids: ["job-1"],
  }));
  await current.closeHandler?.({ preventDefault: vi.fn() });
  expect(await screen.findByRole("dialog", { name: "Close EvidenceForge Studio" })).toBeTruthy();
  expect(invoke).not.toHaveBeenCalledWith("studio_exit");
  await userEvent.setup().selectOptions(
    screen.getByRole("combobox", { name: "Close action for job-1" }), "stop",
  );
  await userEvent.setup().click(screen.getByRole("button", { name: "Apply and close" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith(
    "/v1/session/close", "POST", { generation_exceptions: { "job-1": "stop" } }, 3000,
  ));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith("studio_exit"));
  delete window.__TAURI_INTERNALS__;
});

test("canceling a checkpoint wait restores the open controller intent", async () => {
  Object.assign(window, { __TAURI_INTERNALS__: {} });
  render(<App />);
  const current = getCurrentWindow() as unknown as {
    closeHandler: ((event: { preventDefault: () => void }) => Promise<void>) | null;
  };
  await waitFor(() => expect(current.closeHandler).not.toBeNull());
  const request = vi.mocked(useStudio().api!.request);
  request.mockResolvedValueOnce({ status: "waiting" });
  await current.closeHandler?.({ preventDefault: vi.fn() });
  expect(await screen.findByText("Waiting for checkpoints")).toBeTruthy();
  expect(invoke).not.toHaveBeenCalledWith("studio_exit");
  await userEvent.setup().click(screen.getByRole("button", { name: "Cancel close" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/session/cancel-close", "POST"));
  expect(screen.queryByText("Waiting for checkpoints")).toBeNull();
  delete window.__TAURI_INTERNALS__;
});
