import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { Conversation, StudioApi, StudioEvent } from "../src/api";
import { ChatView } from "../src/ChatView";
import { ChatQuestions } from "../src/ChatQuestions";
import { ChatMarkdown } from "../src/ChatMarkdown";
import { applyChatEvent, finalItemId, type TimelineTurn } from "../src/chatTimeline";

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
const conversation = { id: "chat", thread_id: "thread", title: "Pack", active: true } as Conversation;
const emptyView = { draft: "", skill_name: "", follow_bottom: true, anchor: null, answers: {} };
const seed: TimelineTurn = { id: "turn", status: "inProgress", started_at: Date.now() / 1000 - 24, items: [] };
function harness(turns: TimelineTurn[] = [seed], active = true, pending: unknown[] = []) {
  let emit: (event: StudioEvent) => void = () => undefined;
  let seq = 10;
  const request = vi.fn(async (path: string, method?: string, body?: Record<string, unknown>) => {
    if (path.endsWith("/chat")) return { seq: 10, turns, active_turn_id: active ? "turn" : null, queue: [], queue_paused: false, view: emptyView };
    if (path.endsWith("/pending")) return pending;
    if (path.endsWith("/access")) return { mode: "draft" };
    if (path.endsWith("/messages")) return { id: body?.message_id, state: body?.mode === "queue" ? "queued" : "accepted", turn_id: "turn" };
    if (method === "PUT" || path.endsWith("/reply")) return {};
    return { available: true, account_ready: true };
  });
  const props = { item: { name: "Pack", kind: "industry_pack" as const }, conversation: { ...conversation, active }, codexHealth: { state: "connected" as const, detail: "Connected" }, api: { request } as unknown as StudioApi, subscribeEvents: (listener: (event: StudioEvent) => void) => { emit = listener; return () => undefined; }, onError: vi.fn() };
  const view = render(<ChatView {...props} />);
  const event = (method: string, params: Record<string, unknown>) => act(() => emit({ seq: ++seq, entity_id: "chat", kind: "conversation.event", payload: { method, params: { turnId: "turn", ...params } } }));
  return { ...view, props, request, event };
}

test("commentary, commands and final answers stay ordered and use different presentation", async () => {
  const view = harness();
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/chat"));
  view.event("item/started", { item: { id: "first", type: "agentMessage", phase: "commentary", text: "Starting review" } });
  view.event("item/started", { item: { id: "cmd", type: "commandExecution", command: "eforge pack validate" } });
  view.event("item/started", { item: { id: "second", type: "agentMessage", phase: "commentary", text: "Checking dependencies" } });
  view.event("item/started", { item: { id: "final", type: "agentMessage", phase: "final_answer", text: "The pack is ready" } });
  expect(Array.from(view.container.querySelectorAll("[data-chat-item]")).map((node) => node.getAttribute("data-chat-item"))).toEqual(["first", "cmd", "second", "final"]);
  expect(view.container.querySelectorAll(".chat-commentary")).toHaveLength(2);
  expect(view.container.querySelectorAll(".message-row.agent")).toHaveLength(1);
  expect(screen.getByText("Starting review")).toBeTruthy();
});

test("completed item payloads replace streamed text and failed legacy commentary stays plain", () => {
  const delta = { seq: 1, entity_id: "chat", kind: "conversation.event", payload: { method: "item/agentMessage/delta", params: { turnId: "turn", itemId: "a", delta: "Hello" } } } as StudioEvent;
  const projected = applyChatEvent([], delta);
  const complete = applyChatEvent(projected, { ...delta, seq: 2, payload: { method: "item/completed", params: { turnId: "turn", item: { id: "a", type: "agentMessage", text: "Hello world" } } } });
  expect(complete[0].items[0].text).toBe("Hello world");
  expect(finalItemId({ ...complete[0], status: "failed" })).toBeUndefined();
  expect(finalItemId({ ...complete[0], status: "completed" })).toBe("a");
});

test("Enter queues and the alternate shortcut steers without resetting the turn", async () => {
  vi.spyOn(navigator, "platform", "get").mockReturnValue("MacIntel");
  const view = harness();
  const input = screen.getByRole("textbox", { name: "Message to Codex" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Queue message", exact: true }).hasAttribute("disabled")).toBe(true));
  fireEvent.change(input, { target: { value: "Do this next" } });
  await waitFor(() => expect(screen.getByRole("button", { name: "Queue message", exact: true }).hasAttribute("disabled")).toBe(false));
  fireEvent.keyDown(input, { key: "Enter" });
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ mode: "queue", text: "Do this next" })));
  await waitFor(() => expect((input as HTMLTextAreaElement).value).toBe(""));
  fireEvent.change(input, { target: { value: "A correction" } });
  fireEvent.keyDown(input, { key: "Enter", metaKey: true });
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ mode: "steer", expected_turn_id: "turn", text: "A correction" })));
});

test("opposite shortcut queues for Steer default; Shift, Alt and composition do not send", async () => {
  const view = harness();
  view.rerender(<ChatView {...view.props} followupMode="steer" />);
  const input = screen.getByRole("textbox", { name: "Message to Codex" });
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/chat"));
  fireEvent.change(input, { target: { value: "Message" } });
  fireEvent.keyDown(input, { key: "Enter", shiftKey: true });
  fireEvent.keyDown(input, { key: "Enter", altKey: true });
  fireEvent.keyDown(input, { key: "Enter", isComposing: true });
  expect(view.request.mock.calls.some(([path]) => path.endsWith("/messages"))).toBe(false);
  fireEvent.keyDown(input, { key: "Enter", ctrlKey: true });
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ mode: "queue" })));
});

test("clarification answers stay separate and Other is available when the model omits it", async () => {
  const submit = vi.fn(async () => undefined);
  render(<ChatQuestions questions={[
    { id: "sector", question: "Which sector?", options: [{ label: "Healthcare", description: "Hospital workflows" }] },
    { id: "size", question: "Which size?", options: [{ label: "Small" }] },
  ]} onSubmit={submit} />);
  const user = userEvent.setup();
  expect(submit).not.toHaveBeenCalled();
  await user.click(screen.getAllByRole("radio", { name: "Other" })[1]);
  expect(screen.getByRole("button", { name: "Send answers" }).hasAttribute("disabled")).toBe(true);
  await user.type(screen.getByRole("textbox", { name: "Your answer: Which size?" }), "Two clinics");
  await user.click(screen.getByRole("button", { name: "Send answers" }));
  expect(submit).toHaveBeenCalledWith({ sector: { answers: ["Healthcare"] }, size: { answers: ["Two clinics"] } });
});

test("copy code preserves text despite syntax highlighting", () => {
  const writeText = vi.fn(async () => undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  const view = render(<ChatMarkdown text={'```python\nprint("hello")\n```'} />);
  fireEvent.click(screen.getByRole("button", { name: "Copy code" }));
  expect(writeText).toHaveBeenCalledWith(view.container.querySelector("code")?.textContent);
});

test("live timer becomes a fixed completed duration and retains commentary", async () => {
  const view = harness([{ ...seed, items: [
    { id: "progress", type: "agentMessage", phase: "commentary", text: "Review in progress" },
    { id: "done", type: "agentMessage", phase: "final_answer", text: "Completed review" },
  ] }]);
  expect(await screen.findByText(/Working for 24s/)).toBeTruthy();
  // The terminal event remains visible while authoritative rollout persistence catches up.
  view.event("turn/completed", { turn: { id: "turn", status: "completed", durationMs: 66000 } });
  expect(screen.getByText("Worked for 1m 6s")).toBeTruthy();
  expect(screen.getByText("Review in progress")).toBeTruthy();
});

test("typing while the initial snapshot is loading is preserved over an older saved draft", async () => {
  let resolve: (value: unknown) => void = () => undefined;
  const request = vi.fn(async (path: string) => {
    if (path.endsWith("/chat")) return new Promise((done) => { resolve = done; });
    if (path.endsWith("/pending")) return [];
    return { available: true, account_ready: true };
  });
  render(<ChatView item={{ name: "Pack", kind: "industry_pack" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onError={vi.fn()} />);
  const input = screen.getByRole("textbox", { name: "Message to Codex" }) as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: "My new guidance" } });
  await act(async () => resolve({ seq: 0, turns: [], queue: [], active_turn_id: "turn", queue_paused: false, view: { ...emptyView, draft: "Older draft" } }));
  expect(input.value).toBe("My new guidance");
});

test("snapshot replay keeps live text once and restores the active steering identity", async () => {
  let resolve: (value: unknown) => void = () => undefined;
  let emit: (event: StudioEvent) => void = () => undefined;
  let snapshots = 0;
  const request = vi.fn(async (path: string, method?: string, body?: Record<string, unknown>) => {
    if (path.endsWith("/chat")) {
      if (++snapshots === 1) return new Promise((done) => { resolve = done; });
      return { seq: 4, turns: [{ id: "replayed", status: "inProgress", items: [{ id: "a", type: "agentMessage", phase: "commentary", text: "Live update" }] }], active_turn_id: "replayed", queue: [], view: emptyView };
    }
    if (path.endsWith("/pending")) return [];
    if (path.endsWith("/messages")) return { id: body?.message_id, state: "accepted", turn_id: "replayed" };
    return { available: true, account_ready: true };
  });
  render(<ChatView item={{ name: "Pack", kind: "industry_pack" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={(listener) => { emit = listener; return () => undefined; }} onError={vi.fn()} />);
  for (const [seq, method, params] of [
    [2, "turn/started", { turn: { id: "replayed", status: "inProgress" } }],
    [3, "item/started", { turnId: "replayed", item: { id: "a", type: "agentMessage", phase: "commentary", text: "Live " } }],
    [4, "item/agentMessage/delta", { turnId: "replayed", itemId: "a", delta: "update" }],
  ] as const) act(() => emit({ seq, kind: "conversation.event", entity_id: "chat", payload: { method, params } }));
  await act(async () => resolve({ seq: 1, turns: [], queue: [], active_turn_id: null, view: emptyView }));
  expect(screen.getAllByText("Live update")).toHaveLength(1);
  fireEvent.change(screen.getByRole("textbox", { name: "Message to Codex" }), { target: { value: "Guidance" } });
  fireEvent.keyDown(screen.getByRole("button", { name: "Choose Queue or Steer" }), { key: "ArrowDown" });
  fireEvent.click(await screen.findByRole("menuitem", { name: "Steer current work" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ mode: "steer", expected_turn_id: "replayed" })));
  expect(screen.getAllByText("Live update")).toHaveLength(1);
});

test("Other is not duplicated, free-text answers work, and secret input is never saved", async () => {
  const saved = vi.fn();
  const submit = vi.fn(async () => undefined);
  render(<ChatQuestions questions={[
    { id: "choice", question: "Choose", options: [{ label: "Default" }, { label: "Other" }] },
    { id: "secret", question: "Token", isSecret: true },
  ]} onChange={saved} onSubmit={submit} />);
  expect(screen.getAllByRole("radio", { name: "Other" })).toHaveLength(1);
  const input = screen.getByLabelText("Your answer: Token");
  expect(input.getAttribute("type")).toBe("password");
  fireEvent.change(input, { target: { value: "private-value" } });
  expect(JSON.stringify(saved.mock.calls)).not.toContain("private-value");
  fireEvent.click(screen.getByRole("button", { name: "Send answers" }));
  await waitFor(() => expect(submit).toHaveBeenCalledWith({ choice: { answers: ["Default"] }, secret: { answers: ["private-value"] } }));
});

test("structured asynchronous questions send active-turn guidance and preserve the composer", async () => {
  const view = harness([{ ...seed, items: [{ id: "questions", type: "agentMessage", phase: "commentary", questions: [{ title: "Which sector?", options: ["Healthcare"] }, { title: "Which size?", options: ["Small"] }] }] }]);
  const input = screen.getByRole("textbox", { name: "Message to Codex" });
  await screen.findByText("Which sector?");
  fireEvent.change(input, { target: { value: "My unsent draft" } });
  fireEvent.click(screen.getByRole("button", { name: "Send answers" }));
  await waitFor(() => expect(view.request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ mode: "steer", expected_turn_id: "turn", text: "Which sector?\nHealthcare\n\nWhich size?\nSmall" })));
  expect((input as HTMLTextAreaElement).value).toBe("My unsent draft");
  await waitFor(() => expect(screen.queryByRole("button", { name: "Send answers" })).toBeNull());
});

test("restored uncertain composer delivery reuses its saved client message identity", async () => {
  const request = vi.fn(async (path: string, method?: string, body?: Record<string, unknown>) => {
    if (path.endsWith("/chat")) return { seq: 0, turns: [], queue: [], active_turn_id: null, view: { ...emptyView, draft: "Retry this message", pending_message: { id: "retained-client-id", text: "Retry this message", mode: "start" } } };
    if (path.endsWith("/pending")) return [];
    if (path.endsWith("/messages")) return { id: body?.message_id, state: "accepted", turn_id: "accepted-turn" };
    return { available: true, account_ready: true };
  });
  render(<ChatView item={{ name: "Pack", kind: "industry_pack" }} conversation={{ ...conversation, active: false }}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onError={vi.fn()} />);
  const input = screen.getByRole("textbox", { name: "Message to Codex" }) as HTMLTextAreaElement;
  await waitFor(() => expect(input.value).toBe("Retry this message"));
  fireEvent.click(screen.getByRole("button", { name: "Send message" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.objectContaining({ message_id: "retained-client-id" })));
  expect(request).toHaveBeenCalledWith("/v1/conversations/chat/view", "PUT", expect.objectContaining({ pending_message: { id: "retained-client-id", text: "Retry this message", mode: "start" } }));
});

test("text typed during delivery is retained as the next unsent draft", async () => {
  let delivered: (value: unknown) => void = () => undefined;
  const request = vi.fn(async (path: string) => {
    if (path.endsWith("/chat")) return { seq: 0, turns: [seed], queue: [], active_turn_id: "turn", view: emptyView };
    if (path.endsWith("/messages")) return new Promise((done) => { delivered = done; });
    if (path.endsWith("/pending")) return [];
    return { available: true, account_ready: true };
  });
  render(<ChatView item={{ name: "Pack", kind: "industry_pack" }} conversation={conversation}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onError={vi.fn()} />);
  const input = screen.getByRole("textbox", { name: "Message to Codex" }) as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: "First follow-up" } });
  await waitFor(() => expect(screen.getByRole("button", { name: "Queue message", exact: true }).hasAttribute("disabled")).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Queue message", exact: true }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/conversations/chat/messages", "POST", expect.anything()));
  fireEvent.change(input, { target: { value: "My next draft" } });
  await act(async () => delivered({ id: "sent", state: "queued" }));
  expect(input.value).toBe("My next draft");
});

test("verified results open the source viewer and validate only on request", async () => {
  const request = vi.fn(async (path: string) => {
    if (path.endsWith("/chat")) return { seq: 0, queue: [], active_turn_id: null, view: emptyView, turns: [{ id: "done", status: "completed", items: [{ id: "final", type: "agentMessage", phase: "final_answer", text: "Created the draft" }], results: [{ id: "source", path: "/draft/scenario.yaml", item_id: "scenario", item_kind: "scenario", diff: "Recorded changes" }] }] };
    if (path.includes("/results/")) return { path: "/draft/scenario.yaml", text: "name: draft\n", diff: "Recorded changes" };
    if (path === "/v1/validate") return { exit_code: 0, report: { valid: true } };
    if (path.endsWith("/pending")) return [];
    return { available: true, account_ready: true };
  });
  render(<ChatView item={{ name: "Pack", kind: "industry_pack" }} conversation={{ ...conversation, active: false }}
    codexHealth={{ state: "connected", detail: "Connected" }} api={{ request } as unknown as StudioApi}
    subscribeEvents={() => () => undefined} onError={vi.fn()} />);
  await screen.findByText("scenario.yaml");
  expect(request.mock.calls.some(([path]) => path === "/v1/validate")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "Open source" }));
  expect(await screen.findByLabelText("Preview of /draft/scenario.yaml")).toHaveProperty("textContent", expect.stringContaining("name: draft"));
  fireEvent.click(screen.getByRole("button", { name: "Close", exact: true }));
  fireEvent.click(screen.getByRole("button", { name: "Validate", exact: true }));
  expect(await screen.findByText("Validation passed")).toBeTruthy();
  expect(request).toHaveBeenCalledWith("/v1/validate", "POST", { scenario_id: "scenario" });
});
