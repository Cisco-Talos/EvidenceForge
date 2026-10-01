import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ChatView } from "../src/ChatView";
import type { Conversation, StudioApi, StudioEvent } from "../src/api";

afterEach(() => { cleanup(); });

test("chat renders Markdown and highlighted code while commands and summaries expand individually", async () => {
  const conversation = { id: "rich-chat", title: "Review", active: false } as Conversation;
  const longCommand = `eforge validate ${"long-path/".repeat(25)}scenario.yaml --json`;
  const request = vi.fn(async (path: string) => {
    if (path.endsWith("/history")) return { thread: { turns: [{ id: "turn", items: [
      { type: "agentMessage", text: "## Proposed fixes\n\n**Fix** the host.\n\n- First step\n- Second step\n\n```yaml\nname: valid-name\n```\n\n```python\nprint(42)\n```\n\n```json\n{\"valid\": true}\n```\n\n[guide](https://example.com/guide) [scenario.yaml](/tmp/scenario.yaml) [unsafe](javascript:alert(1))\n<script>alert(1)</script>" },
      { type: "commandExecution", id: "command", command: longCommand, status: "completed", aggregatedOutput: "Full command output" },
      { type: "reasoning", id: "reasoning", summary: ["Check the effective scenario.\nThen validate its hosts.\nMore summary context."], content: ["private reasoning"] },
    ] }] } };
    if (path === "/v1/codex/pending") return [];
    return { available: true };
  });
  const { container } = render(<ChatView item={{ name: "Scenario", kind: "scenario" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onError={vi.fn()} />);
  expect(await screen.findByRole("heading", { name: "Proposed fixes" })).toBeTruthy();
  expect(container.querySelector(".chat-markdown strong")?.textContent).toBe("Fix");
  expect(container.querySelectorAll(".chat-markdown li")).toHaveLength(2);
  expect(container.querySelector("code.language-yaml .hljs-attr")).toBeTruthy();
  expect(container.querySelector("code.language-python .hljs-number")).toBeTruthy();
  expect(container.querySelector("code.language-json .hljs-literal")).toBeTruthy();
  expect(container.querySelector("script")).toBeNull();
  expect(screen.getByText("unsafe").closest("a")).toBeNull();
  expect(screen.getByText("scenario.yaml").closest("a")).toBeNull();
  expect(screen.getByRole("link", { name: "guide" }).getAttribute("href")).toBe("https://example.com/guide");
  expect(screen.queryByText("private reasoning")).toBeNull();
  const user = userEvent.setup();
  await user.click(screen.getByText(/Earlier activity/));
  const command = container.querySelectorAll<HTMLDetailsElement>(".activity-entry")[0];
  expect(command.querySelector(".activity-preview")?.textContent).toHaveLength(181);
  expect(command.open).toBe(false);
  await user.click(command.querySelector("summary")!);
  expect(command.open).toBe(true);
  expect(command.querySelector("pre")?.textContent).toBe(longCommand);
  expect(command.textContent).toContain("Full command output");
  const reasoning = container.querySelectorAll<HTMLDetailsElement>(".activity-entry")[1];
  expect(reasoning.querySelector(".activity-preview")?.textContent).toContain("Check the effective scenario.");
  await user.click(reasoning.querySelector("summary")!);
  expect(reasoning.querySelector(".activity-details")?.textContent).toContain("More summary context.");
});

test("live commands update one activity and reasoning summaries stream into their preview", async () => {
  let emit: (event: StudioEvent) => void = () => undefined;
  const request = vi.fn(async (path: string) => path.endsWith("/history") ? { thread: { turns: [] } } : path.endsWith("/pending") ? [] : { available: true });
  const { container } = render(<ChatView item={{ name: "Scenario", kind: "scenario" }}
    conversation={{ id: "live-chat", title: "Live", active: true } as Conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={(listener) => { emit = listener; return () => undefined; }} onError={vi.fn()} />);
  let seq = 0;
  const event = (method: string, params: Record<string, unknown>) => act(() => emit({ seq: ++seq, entity_id: "live-chat", kind: "conversation.event", payload: { method, params } }));
  event("item/started", { item: { id: "cmd", type: "commandExecution", command: "eforge validate scenario.yaml", status: "inProgress" } });
  event("item/commandExecution/outputDelta", { itemId: "cmd", delta: "No issues found" });
  expect(container.querySelector(".activity-preview")?.textContent).toBe("eforge validate scenario.yaml");
  event("item/completed", { item: { id: "cmd", type: "commandExecution", command: "eforge validate scenario.yaml", status: "completed", aggregatedOutput: "No issues found" } });
  expect(container.querySelectorAll(".activity-entry")).toHaveLength(1);
  expect(screen.getByText("completed")).toBeTruthy();
  event("item/started", { item: { id: "reason", type: "reasoning", summary: [] } });
  event("item/reasoning/summaryTextDelta", { itemId: "reason", summaryIndex: 0, delta: "Checking hosts" });
  expect(container.querySelectorAll(".activity-preview")[1]?.textContent).toBe("Checking hosts");
  expect(container.querySelectorAll(".activity-entry")).toHaveLength(2);
});

test("clicking the conversation title renames inline and Escape cancels", async () => {
  const request = vi.fn(async (path: string) => path.endsWith("/history") ? { thread: { turns: [] } } : path.endsWith("/pending") ? [] : { available: true });
  const onRenamed = vi.fn(async () => undefined);
  render(<ChatView item={{ name: "Scenario", kind: "scenario" }} conversation={{ id: "rename", title: "Old title", active: false } as Conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onRenamed={onRenamed} onError={vi.fn()} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Rename conversation Old title" }));
  await user.clear(screen.getByRole("textbox", { name: "Conversation title" }));
  await user.type(screen.getByRole("textbox", { name: "Conversation title" }), "New title{enter}");
  expect(await screen.findByRole("button", { name: "Rename conversation New title" })).toBeTruthy();
  expect(request).toHaveBeenCalledWith("/v1/conversations/rename", "PATCH", { title: "New title" });
  expect(onRenamed).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Rename conversation New title" }));
  await user.type(screen.getByRole("textbox", { name: "Conversation title" }), "discard{escape}");
  expect(screen.getByRole("button", { name: "Rename conversation New title" })).toBeTruthy();
});

test("a fast follow-up keeps its own user and agent messages when the start event is missed", async () => {
  const conversation = {
    id: "chat-1", workspace: "/tmp/workspace", item_id: "scenario-1", draft_kind: null,
    draft_path: null, draft_project_id: null, draft_name: null, thread_id: "thread-1",
    title: "Scenario review", model_id: null, reasoning_effort: null, active: false,
    needs_attention: false, connection_note: null, updated_at: 1,
  } as Conversation;
  let history = { thread: { turns: [
    { id: "turn-1", status: "completed", items: [
      { type: "userMessage", content: [{ type: "text", text: "First question" }] },
      { type: "agentMessage", text: "First answer" },
    ] },
  ] } };
  const request = vi.fn(async (path: string, method?: string) => {
    if (path.endsWith("/history")) return history;
    if (path === "/v1/codex/status") return { available: true, models: { data: [] }, skills: { data: [] } };
    if (path === "/v1/codex/pending") return [];
    if (path.endsWith("/turns") && method === "POST") {
      history = { thread: { turns: [...history.thread.turns, {
        id: "turn-2", status: "completed", items: [
          { type: "userMessage", content: [{ type: "text", text: "Follow-up question" }] },
          { type: "agentMessage", text: "Second answer" },
        ],
      }] } };
      return { ...conversation, turn_id: "turn-2", delivery: "confirmed" };
    }
    throw new Error(`Unexpected request: ${path}`);
  });
  const onError = vi.fn();
  render(<ChatView
    item={{ name: "Scenario", kind: "scenario" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Codex is responding" }}
    api={{ request } as unknown as StudioApi} subscribeEvents={() => () => undefined}
    onError={onError}
  />);
  expect(await screen.findByText("First answer")).toBeTruthy();
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: "Message to Codex" }), "Follow-up question{enter}");
  expect(await screen.findByText("Second answer")).toBeTruthy();
  await waitFor(() => expect(screen.getAllByText("Follow-up question")).toHaveLength(1));
  expect(screen.getAllByText("First question")).toHaveLength(1);
  expect(screen.getAllByText("First answer")).toHaveLength(1);
  expect(onError).not.toHaveBeenCalled();
});

test("completion arriving before the turn response does not duplicate the submitted message", async () => {
  const conversation = {
    id: "chat-2", workspace: "/tmp/workspace", item_id: "scenario-1", draft_kind: null,
    draft_path: null, draft_project_id: null, draft_name: null, thread_id: "thread-2",
    title: "Scenario review", model_id: null, reasoning_effort: null, active: false,
    needs_attention: false, connection_note: null, updated_at: 1,
  } as Conversation;
  let emit: ((event: StudioEvent) => void) | null = null;
  let history = { thread: { turns: [] as Array<{ id: string; status: string; items: Array<{
    type: string; text?: string; content?: { type: string; text: string }[];
  }> }> } };
  const request = vi.fn(async (path: string, method?: string) => {
    if (path.endsWith("/history")) return history;
    if (path === "/v1/codex/status") return { available: true, models: { data: [] }, skills: { data: [] } };
    if (path === "/v1/codex/pending") return [];
    if (path.endsWith("/turns") && method === "POST") {
      history = { thread: { turns: [{ id: "turn-2", status: "completed", items: [
        { type: "userMessage", content: [{ type: "text", text: "Review this" }] },
        { type: "agentMessage", text: "Reviewed" },
      ] }] } };
      emit?.({ seq: 1, entity_id: "chat-2", kind: "conversation.event", payload: {
        method: "turn/completed", params: { threadId: "thread-2", turn: { id: "turn-2", status: "completed" } },
      } });
      return { ...conversation, active: true, turn_id: "turn-2", delivery: "confirmed" };
    }
    throw new Error(`Unexpected request: ${path}`);
  });
  render(<ChatView
    item={{ name: "Scenario", kind: "scenario" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Codex is responding" }}
    api={{ request } as unknown as StudioApi}
    subscribeEvents={(listener) => { emit = listener; return () => { emit = null; }; }}
    onError={vi.fn()}
  />);
  await userEvent.setup().type(screen.getByRole("textbox", { name: "Message to Codex" }), "Review this{enter}");
  expect(await screen.findByText("Reviewed")).toBeTruthy();
  await waitFor(() => expect(screen.getAllByText("Review this")).toHaveLength(1));
});

test("a signed-out Codex account cannot send a chat turn", async () => {
  const conversation = {
    id: "chat-signed-out", workspace: "/tmp/workspace", item_id: "scenario-1",
    thread_id: null, title: "New conversation", active: false,
  } as Conversation;
  const request = vi.fn(async (path: string) => {
    if (path.endsWith("/history")) return { thread: { turns: [] } };
    if (path === "/v1/codex/status") return {
      available: true, account_ready: false, models: { data: [] }, skills: { data: [] },
    };
    if (path === "/v1/codex/pending") return [];
    throw new Error(`Unexpected request: ${path}`);
  });
  render(<ChatView
    item={{ name: "Scenario", kind: "scenario" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Codex is responding" }}
    api={{ request } as unknown as StudioApi} subscribeEvents={() => () => undefined}
    onError={vi.fn()}
  />);
  await screen.findByText(/Sign in to Codex under Settings/);
  await userEvent.setup().type(screen.getByRole("textbox", { name: "Message to Codex" }), "Hello{enter}");
  expect(screen.getByRole("button", { name: "Send message" }).hasAttribute("disabled")).toBe(true);
  expect(request.mock.calls.some(([path]) => path.endsWith("/turns"))).toBe(false);
});

test("an uncertain submission reconciles from history without duplicating a repeated prompt", async () => {
  const base = {
    id: "chat-uncertain", workspace: "/tmp/workspace", item_id: "scenario-1",
    thread_id: "thread-uncertain", title: "Review", active: false,
  } as Conversation;
  const oldTurn = { id: "old-turn", status: "completed", items: [
    { type: "userMessage", content: [{ type: "text", text: "Review this" }] },
    { type: "agentMessage", text: "Earlier review" },
  ] };
  let history = { thread: { turns: [oldTurn] } };
  const request = vi.fn(async (path: string, method?: string) => {
    if (path.endsWith("/history")) return history;
    if (path === "/v1/codex/status") return { available: true, account_ready: true, models: { data: [] }, skills: { data: [] } };
    if (path === "/v1/codex/pending") return [];
    if (path.endsWith("/turns") && method === "POST") return { ...base, active: true, turn_id: null, delivery: "uncertain" };
    throw new Error(`Unexpected request: ${path}`);
  });
  const renderView = (conversation: Conversation) => <ChatView
    item={{ name: "Scenario", kind: "scenario" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Codex is responding" }}
    api={{ request } as unknown as StudioApi} subscribeEvents={() => () => undefined}
    onError={vi.fn()}
  />;
  const view = render(renderView(base));
  expect(await screen.findByText("Earlier review")).toBeTruthy();
  await userEvent.setup().type(screen.getByRole("textbox", { name: "Message to Codex" }), "Review this{enter}");
  await waitFor(() => expect(request.mock.calls.some(([path]) => path.endsWith("/turns"))).toBe(true));
  view.rerender(renderView({ ...base, active: true }));
  history = { thread: { turns: [oldTurn, { id: "new-turn", status: "completed", items: [
    { type: "userMessage", content: [{ type: "text", text: "Review this" }] },
    { type: "agentMessage", text: "Updated review" },
  ] }] } };
  view.rerender(renderView(base));
  expect(await screen.findByText("Updated review")).toBeTruthy();
  await waitFor(() => expect(screen.getAllByText("Review this")).toHaveLength(2));
});
