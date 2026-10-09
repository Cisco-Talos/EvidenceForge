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
    request: vi.fn(async (path: string) => path === "/v1/state/status" ? { state: "ready" } : path === "/v1/bootstrap" ? snapshot : {}),
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
  const warning = { path: "/private/old-runtime", message: "Cannot verify process ownership." };
  act(() => onEvent?.({ seq: 7, entity_id: "runtime", kind: "runtime.cleanup", payload: { warnings: [warning] } }));
  expect(result.current.snapshot?.runtime_cleanup?.warnings).toEqual([warning]);
  act(() => onEvent?.({ seq: 8, entity_id: "runtime", kind: "runtime.cleanup", payload: { warnings: [] } }));
  expect(result.current.snapshot?.runtime_cleanup?.warnings).toEqual([]);
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
    request: vi.fn(async (path: string) => path === "/v1/state/status" ? { state: "ready" } : snapshot),
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

test("upgrade waits for human acceptance while normal endpoints stay gated", async () => {
  const pending = { state: "pending", operation_id: "a".repeat(32), warning: "Earlier builds will no longer open this state", error: null };
  const request = vi.fn(async (path: string) => path === "/v1/state/status" ? pending : {});
  vi.mocked(connectStudio).mockResolvedValue({ request } as unknown as StudioApi);
  const { result, unmount } = renderHook(() => useStudio());
  await waitFor(() => expect(result.current.maintenance?.warning).toBe(pending.warning));
  expect(request).not.toHaveBeenCalledWith("/v1/session/open", "POST");
  expect(request.mock.calls.filter(([path]) => path === "/v1/state/upgrade")).toHaveLength(0);
  vi.useFakeTimers();
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(request.mock.calls.filter(([path]) => path === "/v1/state/upgrade")).toHaveLength(0);
  expect(result.current.maintenance?.state).toBe("pending");
  await act(async () => { await result.current.recoverState(); });
  expect(request).toHaveBeenCalledWith("/v1/state/upgrade", "POST", { operation_id: pending.operation_id });
  expect(result.current.snapshot).toBeNull();
  expect(result.current.maintenance?.state).toBe("running");
  unmount(); vi.useRealTimers();
});

test("completion notice is consumed once and is not replayed on reconnect or restart", async () => {
  const operation_id = "a".repeat(32);
  let status = { state: "pending", operation_id, warning: "Studio will upgrade your saved UI state", error: null, backup_path: null as string | null };
  let disconnected: (() => void) | undefined;
  const snapshot = { seq: 1, conversations: [], projects: [], folders: [], views: [] } as unknown as StudioSnapshot;
  const client = {
    request: vi.fn(async (path: string) => {
      if (path === "/v1/state/upgrade") { status = { ...status, state: "ready", backup_path: "/private/recovery" }; return status; }
      return path === "/v1/state/status" ? status : path === "/v1/bootstrap" ? snapshot : {};
    }),
    subscribe: vi.fn((_after, _event, disconnect) => { disconnected = disconnect; return { close: vi.fn() } as unknown as WebSocket; }),
  } as unknown as StudioApi;
  vi.mocked(connectStudio).mockResolvedValue(client);
  const first = renderHook(useStudio);
  await waitFor(() => expect(first.result.current.maintenance?.state).toBe("pending"));
  await act(async () => { await first.result.current.recoverState(); });
  await waitFor(() => expect(first.result.current.snapshot).not.toBeNull());
  expect(first.result.current.upgradeNotice).toBe("Studio UI state upgraded successfully. Recovery backup: /private/recovery");
  act(() => first.result.current.clearUpgradeNotice());
  vi.useFakeTimers();
  act(() => disconnected?.());
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(first.result.current.upgradeNotice).toBeNull();
  first.unmount(); vi.useRealTimers();
  const second = renderHook(useStudio);
  await waitFor(() => expect(second.result.current.snapshot).not.toBeNull());
  expect(second.result.current.upgradeNotice).toBeNull();
  second.unmount();
});

for (const state of ["failed", "blocked", "restored"] as const) {
  test(`${state} state does not automatically restart an upgrade or open a session`, async () => {
    const request = vi.fn(async () => ({ state, error: "Recovery required", operation_id: "a".repeat(32) }));
    vi.mocked(connectStudio).mockResolvedValue({ request } as unknown as StudioApi);
    const { result, unmount } = renderHook(() => useStudio());
    await waitFor(() => expect(result.current.maintenance?.state).toBe(state));
    expect(request).toHaveBeenCalledWith("/v1/session/heartbeat", "POST");
    expect(request).toHaveBeenCalledWith("/v1/state/status");
    expect(request).not.toHaveBeenCalledWith("/v1/session/open", "POST");
    expect(result.current.snapshot).toBeNull();
    unmount();
  });
}

test("maintenance keeps its window lease alive and stops heartbeats on unmount", async () => {
  vi.useFakeTimers();
  const request = vi.fn(async (path: string) => path === "/v1/state/status"
    ? { state: "blocked", operation_id: "op", error: "Newer saved state" } : {});
  vi.mocked(connectStudio).mockResolvedValue({ request } as unknown as StudioApi);
  const hook = renderHook(useStudio);
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(hook.result.current.maintenance?.state).toBe("blocked");
  expect(request.mock.calls.filter(([path]) => path === "/v1/session/heartbeat")).toHaveLength(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
  expect(request.mock.calls.filter(([path]) => path === "/v1/session/heartbeat")).toHaveLength(2);
  expect(request).not.toHaveBeenCalledWith("/v1/session/open", "POST");
  hook.unmount();
  await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
  expect(request.mock.calls.filter(([path]) => path === "/v1/session/heartbeat")).toHaveLength(2);
  vi.useRealTimers();
});
