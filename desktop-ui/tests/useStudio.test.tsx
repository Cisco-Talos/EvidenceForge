import { act, renderHook, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { connectStudio, StudioApi, StudioEvent, StudioSnapshot } from "../src/api";
import { useStudio } from "../src/useStudio";

vi.mock("../src/api", () => ({ connectStudio: vi.fn() }));

test("live service connection and Codex health update independently", async () => {
  const snapshot = {
    seq: 1,
    codex_health: { state: "connected", detail: "Codex is responding" },
    conversations: [],
    projects: [],
    folders: [],
    views: [],
  } as StudioSnapshot;
  let onEvent: ((event: StudioEvent) => void) | undefined;
  let onDisconnect: (() => void) | undefined;
  let onOpen: (() => void) | undefined;
  const socket = { close: vi.fn() } as unknown as WebSocket;
  const client = {
    request: vi.fn(async (path: string) => path === "/v1/bootstrap" ? snapshot : {}),
    subscribe: vi.fn((
      _after: number,
      event: (value: StudioEvent) => void,
      disconnect: () => void,
      open: () => void,
    ) => {
      onEvent = event;
      onDisconnect = disconnect;
      onOpen = open;
      return socket;
    }),
  } as unknown as StudioApi;
  vi.mocked(connectStudio).mockResolvedValue(client);

  const { result, unmount } = renderHook(() => useStudio());
  await waitFor(() => expect(result.current.snapshot).not.toBeNull());
  expect(result.current.liveState).toBe("connecting");
  act(() => onOpen?.());
  expect(result.current.liveState).toBe("connected");
  act(() => onEvent?.({
    seq: 2, entity_id: "codex", kind: "codex.health",
    payload: { state: "stalled", detail: "Codex timed out" },
  }));
  expect(result.current.snapshot?.codex_health.state).toBe("stalled");
  const received: string[] = [];
  const unsubscribe = result.current.subscribeEvents((event) => received.push(event.kind));
  act(() => {
    onEvent?.({ seq: 3, entity_id: "chat-1", kind: "conversation.event", payload: {
      method: "turn/completed", params: { turn: { id: "turn-1" } },
    } });
    onEvent?.({ seq: 4, entity_id: "chat-1", kind: "conversation.updated", payload: {} });
  });
  expect(received).toEqual(["conversation.event", "conversation.updated"]);
  act(() => onEvent?.({ seq: 5, entity_id: "scenario", kind: "scenario.dependencies", payload: { ready: true, fingerprint: "fresh-pack-digest", rows: [], changed_at: 123 } }));
  expect(result.current.snapshot?.dependencies?.scenario.fingerprint).toBe("fresh-pack-digest");
  expect(result.current.snapshot?.dependencies?.scenario.ready).toBe(true);
  act(() => onEvent?.({ seq: 6, entity_id: "scenario", kind: "scenario.forecast", payload: {
    source_sha256: "sha", dependency_fingerprint: "fresh-pack-digest", input_fingerprint: "key", completed_at: 124,
    result: { available: false, error: "Missing exact pack", destination: "/workspace/runs", checkpoint_hours: 24 },
  } }));
  expect(result.current.snapshot?.forecasts?.scenario.result.error).toBe("Missing exact pack");
  unsubscribe();
  act(() => onDisconnect?.());
  expect(result.current.liveState).toBe("disconnected");
  unmount();
  expect(socket.close).toHaveBeenCalled();
});

test("history cleanup events retain run metadata and a resumed job reappears", async () => {
  const snapshot = { seq: 1, conversations: [], jobs: [
    { id: "run", kind: "generation", status: "completed", output_root: "/tmp/run" },
  ], removed_job_ids: [] } as unknown as StudioSnapshot;
  let onEvent: ((event: StudioEvent) => void) | undefined;
  const client = {
    request: vi.fn(async () => snapshot),
    subscribe: vi.fn((_after: number, event: (value: StudioEvent) => void) => {
      onEvent = event;
      return { close: vi.fn() } as unknown as WebSocket;
    }),
  } as unknown as StudioApi;
  vi.mocked(connectStudio).mockResolvedValue(client);
  const { result, unmount } = renderHook(useStudio);
  await waitFor(() => expect(result.current.snapshot).not.toBeNull());
  act(() => onEvent?.({ seq: 2, entity_id: "run", kind: "job.history_removed", payload: { job_ids: ["run"] } }));
  expect(result.current.snapshot?.removed_job_ids).toEqual(["run"]);
  expect(result.current.snapshot?.jobs).toHaveLength(1);
  act(() => onEvent?.({ seq: 3, entity_id: "run", kind: "job.updated", payload: { ...snapshot.jobs[0], status: "queued" } }));
  expect(result.current.snapshot?.removed_job_ids).toEqual([]);
  expect(result.current.snapshot?.jobs[0].status).toBe("queued");
  unmount();
});
