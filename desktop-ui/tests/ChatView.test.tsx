import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ChatView } from "../src/ChatView";
import type { Conversation, StudioApi, StudioEvent } from "../src/api";

afterEach(() => { cleanup(); });

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
