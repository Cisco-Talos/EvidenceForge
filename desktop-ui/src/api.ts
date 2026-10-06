import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { components } from "./generated/studio";

type Schema = components["schemas"];
export type UpgradeStatus = Schema["UpgradeStatus"];
export type ItemKind = Schema["CatalogItem"]["kind"];
// The service serializes every model field in snapshots, including fields with defaults.
type PackMetadata = "publisher" | "publisher_display_name" | "requires_evidenceforge" | "pack_source" | "search_excerpt" | "search_field" | "search_matches" | "search_match_count" | "search_revision";
export type CatalogItem = Omit<Required<Schema["CatalogItem"]>, PackMetadata> & Pick<Schema["CatalogItem"], PackMetadata>;
export type ImportedBundle = Required<Schema["ImportedBundle"]>;
export type Project = Omit<Required<Schema["Project"]>, "overlay_enabled"> & Pick<Schema["Project"], "overlay_enabled">;
type PackViewFilters = "publisher" | "version" | "pack_source" | "sort";
export type SavedView = Omit<Required<Schema["SavedView"]>, PackViewFilters> & Pick<Schema["SavedView"], PackViewFilters>;
export type Conversation = Required<Schema["Conversation"]>;
export type TurnSubmission = Required<Schema["TurnSubmission"]>;
export type CodexHealth = Required<Schema["CodexHealth"]>;
export type QuitSettings = Required<Schema["QuitSettings"]>;
export type StudioSettings = Omit<Required<Schema["StudioSettings"]>, "quit"> & { quit: QuitSettings };
export type RuntimeCleanupReport = Schema["RuntimeCleanupReport"];
export type GenerationProgress = Required<Schema["GenerationProgress"]>;
export type StudioJob = Schema["JobSummary"];
export type ScorecardDetail = Schema["ScorecardDetail"];
export type PackPublisherStatus = Schema["PackPublisherStatus"];
export type PackCreation = { item: CatalogItem; conversation: Conversation };
export type PackReview = Schema["PackReview"];
export type PackDeleteReview = Schema["PackDeleteReview"];
export type PackDeleted = Schema["PackDeleted"];
export type LibraryView = Required<Schema["LibraryView"]>;
export type LibraryPreferences = Schema["LibraryPreferences"];
export type AssetPage = Required<Schema["AssetPage"]>;
export type AssetDetail = Required<Omit<Schema["AssetDetail"], "inherited_value" | "override_fields" | "conversion_from" | "conversion_effects" | "previous_value">> & Pick<Schema["AssetDetail"], "inherited_value" | "override_fields" | "conversion_from" | "conversion_effects" | "previous_value">;
export type AssetOrigin = Schema["AssetOrigin"];
export type AssetSaved = Schema["AssetSaved"];
export type AssetChoices = Required<Schema["AssetChoices"]>;
export type EnvironmentReport = Omit<Required<Schema["EnvironmentReport"]>, "configuration"> & Pick<Schema["EnvironmentReport"], "configuration">;
export type PredictionRecord = Required<Schema["PredictionRecord"]>;
export type SelectedPack = Schema["SelectedPack"];
export type ImportReview = Omit<Schema["ImportReview"], "rows"> & { rows: DependencyRow[] };
export type DependencyRow = Schema["DependencyRow"];
export type DependencyHealth = Schema["DependencyHealth"];
export type ImportResult = Omit<Schema["ImportResult"], "item"> & { item?: CatalogItem | null };
export type StudioSnapshot = Omit<Schema["StudioSnapshot"], "settings" | "items" | "projects" | "views" | "conversations" | "jobs" | "codex_health" | "validations" | "imported_bundles"> & {
  settings: StudioSettings;
  items: CatalogItem[];
  projects: Project[];
  views: SavedView[];
  conversations: Conversation[];
  jobs: StudioJob[];
  imported_bundles: ImportedBundle[];
  codex_health: CodexHealth;
  validations: Record<string, ValidationRecord>;
};

export interface StudioEvent {
  seq: number;
  entity_id: string;
  kind: string;
  payload: Record<string, unknown>;
}

export interface TextPreview { text: string; truncated: boolean; binary: boolean }
export interface ExportProgress { id: string; bytes: number; total: number | null }
export type DownloadResult = { status: "saved"; path: string } | { status: "cancelled" } | { status: "browser" };

export type ValidationResult = Required<Schema["ValidationResult"]>;
export type ValidationRecord = Schema["ValidationRecord"];

interface Connection {
  url: string;
  token: string;
}

// A renderer keeps its identity across reconnects; separate windows get separate IDs.
const windowSession = crypto.randomUUID();

export class StudioApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `${status} request failed`);
    this.status = status;
    this.detail = detail;
  }
}

export class StudioApi {
  readonly url: string;
  readonly token: string;

  constructor(connection: Connection) {
    this.url = connection.url;
    this.token = connection.token;
  }

  async libraryPreferences(workspace: string): Promise<LibraryPreferences> {
    return this.request(`/v1/library/preferences?workspace=${encodeURIComponent(workspace)}`);
  }

  async saveLibraryView(workspace: string, kind: "scenarios" | "packs", view: LibraryView): Promise<LibraryView> {
    return this.request(`/v1/library/view/${kind}?workspace=${encodeURIComponent(workspace)}`, "PUT", view);
  }

  async bundleSizes(): Promise<Record<string, number | null>> {
    return this.request("/v1/jobs/bundle-sizes");
  }

  async request<T>(path: string, method = "GET", body?: unknown, timeoutMs = 15000): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetch(`${this.url}${path}`, {
      method,
      signal: controller.signal,
      headers: {
        "X-EForge-Token": this.token,
        "X-EForge-Session": windowSession,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      let detail: unknown = `${response.status} ${response.statusText}`;
      try {
        const error = (await response.json()) as { detail?: unknown };
        detail = error.detail || detail;
      } catch {
        // Keep the HTTP status when no JSON error is available.
      }
      throw new StudioApiError(response.status, detail);
    }
    return (await response.json()) as T;
  }

  private async nativeDownload(path: string, filename: string, onProgress?: (progress: ExportProgress) => void): Promise<DownloadResult> {
    const id = crypto.randomUUID();
    const location = await this.request<{ directory: string | null }>("/v1/export-location").catch(() => ({ directory: null }));
    const unlisten = await listen<ExportProgress>("studio-export-progress", (event) => {
      if (event.payload.id === id) onProgress?.(event.payload);
    });
    try {
      const saved = await invoke<string | null>("save_studio_export", {
        id, baseUrl: this.url, token: this.token, path, filename,
        initialDirectory: location.directory,
      });
      if (!saved) return { status: "cancelled" };
      const separator = Math.max(saved.lastIndexOf("/"), saved.lastIndexOf("\\"));
      if (separator > 0) {
        await this.request("/v1/export-location", "PUT", { directory: saved.slice(0, separator) }).catch(() => undefined);
      }
      return { status: "saved", path: saved };
    } finally {
      unlisten();
    }
  }

  async cancelExport(id: string): Promise<void> {
    if (isTauri()) await invoke("cancel_studio_export", { id });
  }

  async download(path: string, filename: string, onProgress?: (progress: ExportProgress) => void): Promise<DownloadResult> {
    if (isTauri()) return this.nativeDownload(path, filename, onProgress);
    const response = await fetch(`${this.url}${path}`, {
      headers: { "X-EForge-Token": this.token },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({})) as { detail?: string };
      throw new StudioApiError(response.status, payload.detail || response.statusText);
    }
    const objectUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    return { status: "browser" };
  }

  async downloadBundle(jobId: string, filename = `run-${jobId.slice(0, 8)}.zip`, onProgress?: (progress: ExportProgress) => void): Promise<DownloadResult> {
    if (isTauri()) return this.nativeDownload(`/v1/jobs/${encodeURIComponent(jobId)}/bundle.zip`, filename, onProgress);
    const { ticket } = await this.request<{ ticket: string }>(
      `/v1/jobs/${encodeURIComponent(jobId)}/bundle.zip/ticket`, "POST",
    );
    const link = document.createElement("a");
    link.href = `${this.url}/v1/jobs/${encodeURIComponent(jobId)}/bundle.zip?ticket=${encodeURIComponent(ticket)}`;
    document.body.append(link);
    link.click();
    link.remove();
    return { status: "browser" };
  }

  async readTextPreview(path: string, maxBytes = 256 * 1024): Promise<TextPreview> {
    const response = await fetch(`${this.url}${path}`, {
      headers: { "X-EForge-Token": this.token, Range: `bytes=0-${maxBytes - 1}` },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({})) as { detail?: string };
      throw new StudioApiError(response.status, payload.detail || response.statusText);
    }
    if (!response.body) throw new Error("This browser cannot stream bundle files.");
    const reader = response.body.getReader();
    const bytes = new Uint8Array(maxBytes);
    let length = 0;
    let truncated = false;
    while (length < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const count = Math.min(value.length, maxBytes - length);
      bytes.set(value.subarray(0, count), length);
      length += count;
      if (count < value.length) { truncated = true; break; }
    }
    if (length === maxBytes) {
      const total = response.headers.get("Content-Range")?.match(/\/(\d+)$/)?.[1];
      truncated = truncated || (total ? Number(total) > maxBytes : true);
    }
    await reader.cancel();
    const content = bytes.subarray(0, length);
    const binary = content.includes(0);
    return { text: binary ? "" : new TextDecoder().decode(content), truncated, binary };
  }

  subscribe(after: number, onEvent: (event: StudioEvent) => void, onDisconnect: () => void, onOpen: () => void): WebSocket {
    const url = new URL(this.url);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = "/v1/events/ws";
    url.searchParams.set("token", this.token);
    url.searchParams.set("after", String(after));
    const socket = new WebSocket(url);
    socket.onopen = onOpen;
    socket.onmessage = (message) => onEvent(JSON.parse(message.data) as StudioEvent);
    socket.onclose = onDisconnect;
    socket.onerror = () => socket.close();
    return socket;
  }
}

export async function connectStudio(): Promise<StudioApi> {
  const devUrl = import.meta.env.VITE_STUDIO_URL as string | undefined;
  const devToken = import.meta.env.VITE_STUDIO_TOKEN as string | undefined;
  if (devUrl && devToken) {
    return new StudioApi({ url: devUrl, token: devToken });
  }
  const connection = await invoke<Connection>("studio_connection");
  return new StudioApi(connection);
}
