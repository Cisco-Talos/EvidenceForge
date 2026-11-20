import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { Conversation } from "../src/api";
import { RecentConversations } from "../src/RecentConversations";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const chat = (id: string, overrides: Partial<Conversation> = {}) => ({
  id, workspace: "/w", item_id: "alpha", draft_kind: null, draft_path: null, draft_project_id: null, thread_id: null,
  title: `Chat ${id}`, model_id: null, reasoning_effort: null, active: false, needs_attention: false, connection_note: null, updated_at: 1800000000,
  ...overrides,
}) as Conversation;
const chats = ["1", "2", "3", "4", "5"].map((id) => chat(id));

test("recent conversations show three rows without layout measurement and open the chosen conversation", async () => {
  vi.stubGlobal("ResizeObserver", undefined);
  const onOpen = vi.fn();
  render(<RecentConversations conversations={[chat("1", { needs_attention: true, active: true }), chat("2", { active: true }), ...chats.slice(2)]} onOpen={onOpen} />);
  const list = screen.getByRole("list", { name: "Recent conversations" });
  const rows = within(list).getAllByRole("button");
  expect(rows.map((row) => row.getAttribute("aria-label"))).toEqual(["Open Chat 1", "Open Chat 2", "Open Chat 3"]);
  expect(rows.map((row) => row.querySelector("em")?.textContent ?? null)).toEqual(["Needs input", "Working", null]);
  expect(rows[0].querySelector("time")).toHaveAttribute("dateTime", new Date(1800000000 * 1000).toISOString());
  await userEvent.setup().click(rows[1]);
  expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: "2" }));
});

test("recent conversations fit as many rows as the measured space allows, at least one", () => {
  let report!: (height: number) => void;
  const disconnect = vi.fn();
  vi.stubGlobal("ResizeObserver", class {
    constructor(callback: (entries: { contentRect: { height: number } }[]) => void) { report = (height) => callback([{ contentRect: { height } }]); }
    observe() {}
    disconnect() { disconnect(); }
  });
  const { unmount } = render(<RecentConversations conversations={chats} onOpen={vi.fn()} />);
  const count = () => within(screen.getByRole("list", { name: "Recent conversations" })).getAllByRole("button").length;
  act(() => report(32 * 4 + 10));
  expect(count()).toBe(4);
  act(() => report(1000));
  expect(count()).toBe(5);
  act(() => report(0));
  expect(count()).toBe(1);
  unmount();
  expect(disconnect).toHaveBeenCalled();
});

test("recent conversations render nothing when there are none", () => {
  const { container } = render(<RecentConversations conversations={[]} onOpen={vi.fn()} />);
  expect(container).toBeEmptyDOMElement();
});
