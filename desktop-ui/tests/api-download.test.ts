import { afterEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { StudioApi } from "../src/api";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true, invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

afterEach(() => { vi.clearAllMocks(); vi.unstubAllGlobals(); });

test("window identity survives API reconnects and is attached to lifecycle requests", async () => {
  const fetch = vi.fn(async (_url: string, _options: RequestInit) => Response.json({ status: "ok" }));
  vi.stubGlobal("fetch", fetch);
  await new StudioApi({ url: "http://127.0.0.1:4400", token: "secret" }).request("/v1/session/heartbeat", "POST");
  await new StudioApi({ url: "http://127.0.0.1:4400", token: "secret" }).request("/v1/session/close", "POST");
  const first = fetch.mock.calls[0][1] as RequestInit;
  const second = fetch.mock.calls[1][1] as RequestInit;
  const id = (first.headers as Record<string, string>)["X-EForge-Session"];
  expect(id).toMatch(/^[\da-f-]{36}$/);
  expect((second.headers as Record<string, string>)["X-EForge-Session"]).toBe(id);
});

test("native file save uses the system command and remembers the workspace folder", async () => {
  const unlisten = vi.fn();
  const onProgress = vi.fn();
  const fetch = vi.fn(async (_url: string, options: RequestInit) =>
    Response.json(options.method === "PUT" ? { directory: "/tmp/exports" } : { directory: "/tmp/previous" }));
  vi.stubGlobal("fetch", fetch);
  vi.stubGlobal("crypto", { randomUUID: () => "export-1" });
  vi.mocked(listen).mockImplementation(async (_event, listener) => {
    listener({ payload: { id: "export-1", bytes: 1024, total: 2048 } } as Parameters<typeof listener>[0]);
    return unlisten;
  });
  vi.mocked(invoke).mockResolvedValue("/tmp/exports/artifact.json");

  const result = await new StudioApi({ url: "http://127.0.0.1:4400", token: "secret" })
    .download("/v1/jobs/run-1/files/artifact.json", "artifact.json", onProgress);

  expect(result).toEqual({ status: "saved", path: "/tmp/exports/artifact.json" });
  expect(invoke).toHaveBeenCalledWith("save_studio_export", {
    id: "export-1", baseUrl: "http://127.0.0.1:4400", token: "secret",
    path: "/v1/jobs/run-1/files/artifact.json", filename: "artifact.json",
    initialDirectory: "/tmp/previous",
  });
  expect(onProgress).toHaveBeenCalledWith({ id: "export-1", bytes: 1024, total: 2048 });
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(fetch.mock.calls[1][1]).toMatchObject({ method: "PUT", body: JSON.stringify({ directory: "/tmp/exports" }) });
  expect(unlisten).toHaveBeenCalledOnce();
});

test("cancelled native save does not change the export folder", async () => {
  const fetch = vi.fn(async () => Response.json({ directory: null }));
  vi.stubGlobal("fetch", fetch);
  vi.stubGlobal("crypto", { randomUUID: () => "export-2" });
  vi.mocked(listen).mockResolvedValue(vi.fn());
  vi.mocked(invoke).mockResolvedValue(null);

  const result = await new StudioApi({ url: "http://127.0.0.1:4400", token: "secret" })
    .downloadBundle("run-1", "run-1.zip");

  expect(result).toEqual({ status: "cancelled" });
  expect(invoke).toHaveBeenCalledWith("save_studio_export", expect.objectContaining({
    path: "/v1/jobs/run-1/bundle.zip", filename: "run-1.zip",
  }));
  expect(fetch).toHaveBeenCalledTimes(1);
});
