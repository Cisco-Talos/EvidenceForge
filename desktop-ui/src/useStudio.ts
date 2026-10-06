import { useCallback, useEffect, useRef, useState } from "react";
import {
  CatalogItem,
  ImportedBundle,
  Conversation,
  CodexHealth,
  connectStudio,
  Project,
  SavedView,
  StudioApi,
  StudioEvent,
  StudioJob,
  StudioSettings,
  StudioSnapshot,
  ValidationResult,
  UpgradeStatus,
} from "./api";

export interface StudioState {
  maintenance: UpgradeStatus | null;
  upgradeNotice: string | null;
  clearUpgradeNotice: () => void;
  recoverState: (restore?: boolean) => Promise<void>;
  selectRecoveryWorkspace: (path: string) => Promise<void>;
  api: StudioApi | null;
  snapshot: StudioSnapshot | null;
  error: string | null;
  liveState: "connecting" | "connected" | "disconnected";
  validations: Record<string, ValidationResult>;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  reload: () => Promise<void>;
}

function applyEvent(snapshot: StudioSnapshot, event: StudioEvent): StudioSnapshot {
  if (event.seq <= snapshot.seq) return snapshot;
  const next = { ...snapshot, seq: event.seq };
  if (event.kind === "item.updated") {
    const item = event.payload as unknown as CatalogItem;
    next.items = snapshot.items.map((existing) => (existing.id === item.id ? item : existing));
  } else if (event.kind === "project.created" || event.kind === "project.updated") {
    const project = event.payload as unknown as Project;
    next.projects = [...snapshot.projects.filter((existing) => existing.id !== project.id), project]
      .sort((a, b) => a.name.localeCompare(b.name));
  } else if (event.kind === "project.deleted") {
    next.projects = snapshot.projects.filter((existing) => existing.id !== event.entity_id);
  } else if (event.kind === "view.saved") {
    const view = event.payload as unknown as SavedView;
    next.views = [...snapshot.views.filter((existing) => existing.name !== view.name), view]
      .sort((a, b) => a.name.localeCompare(b.name));
  } else if (event.kind === "view.deleted") {
    next.views = snapshot.views.filter((existing) => existing.name !== event.entity_id);
  } else if (event.kind === "conversation.created" || event.kind === "conversation.updated") {
    const conversation = event.payload as unknown as Conversation;
    next.conversations = [
      conversation,
      ...snapshot.conversations.filter((existing) => existing.id !== conversation.id),
    ];
  } else if (event.kind === "conversation.deleted") {
    next.conversations = snapshot.conversations.filter((existing) => existing.id !== event.entity_id);
  } else if (event.kind === "job.created" || event.kind === "job.updated") {
    const job = event.payload as unknown as StudioJob;
    next.jobs = [job, ...snapshot.jobs.filter((existing) => existing.id !== job.id)];
    if (["queued", "running", "paused"].includes(job.status)) {
      next.removed_job_ids = snapshot.removed_job_ids?.filter((id) => id !== job.id);
    }
  } else if (event.kind === "job.deleted") {
    next.jobs = snapshot.jobs.filter((existing) => existing.id !== event.entity_id);
    next.removed_job_ids = snapshot.removed_job_ids?.filter((id) => id !== event.entity_id);
  } else if (event.kind === "job.history_removed") {
    next.removed_job_ids = [...new Set([...(snapshot.removed_job_ids || []), ...event.payload.job_ids as string[]])];
  } else if (event.kind === "bundle.imported") {
    const bundle = event.payload as unknown as ImportedBundle;
    next.imported_bundles = [bundle, ...snapshot.imported_bundles.filter((entry) => entry.id !== bundle.id)];
  } else if (event.kind === "bundle.removed") {
    next.imported_bundles = snapshot.imported_bundles.filter((entry) => entry.id !== event.entity_id);
  } else if (event.kind === "settings.updated") {
    next.settings = event.payload as unknown as StudioSettings;
  } else if (event.kind === "scenario.validated") {
    next.validations = {
      ...snapshot.validations,
      [event.entity_id]: event.payload as unknown as StudioSnapshot["validations"][string],
    };
  } else if (event.kind === "scenario.dependencies") {
    next.dependencies = { ...snapshot.dependencies, [event.entity_id]: event.payload as unknown as NonNullable<StudioSnapshot["dependencies"]>[string] };
  } else if (event.kind === "scenario.forecast") {
    next.forecasts = { ...snapshot.forecasts, [event.entity_id]: event.payload as unknown as NonNullable<StudioSnapshot["forecasts"]>[string] };
  } else if (event.kind === "codex.health") {
    next.codex_health = event.payload as unknown as CodexHealth;
  }
  return next;
}

export function useStudio(): StudioState {
  const [maintenance, setMaintenance] = useState<UpgradeStatus | null>(null);
  const [upgradeNotice, setUpgradeNotice] = useState<string | null>(null);
  const [recoveryRevision, setRecoveryRevision] = useState(0);
  const [api, setApi] = useState<StudioApi | null>(null);
  const [snapshot, setSnapshot] = useState<StudioSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [validations, setValidations] = useState<Record<string, ValidationResult>>({});
  const socketRef = useRef<WebSocket | null>(null);
  const apiRef = useRef<StudioApi | null>(null);
  const observedOperation = useRef<string | null>(null);
  const acceptedOperations = useRef(new Set<string>());
  const recoveryInFlight = useRef(false);
  const eventListeners = useRef(new Set<(event: StudioEvent) => void>());
  const clearUpgradeNotice = useCallback(() => setUpgradeNotice(null), []);

  const subscribeEvents = useCallback((listener: (event: StudioEvent) => void) => {
    eventListeners.current.add(listener);
    return () => { eventListeners.current.delete(listener); };
  }, []);

  const reload = useCallback(async () => {
    const client = apiRef.current;
    if (!client) return;
    const fresh = await client.request<StudioSnapshot>("/v1/bootstrap");
    setSnapshot(fresh);
  }, []);

  const recoverState = useCallback(async (restore = false) => {
    if (!apiRef.current || !maintenance || recoveryInFlight.current || maintenance.state === "running") return;
    recoveryInFlight.current = true;
    const previous = maintenance;
    acceptedOperations.current.add(maintenance.operation_id);
    setError(null);
    setMaintenance({ ...maintenance, state: "running", phase: restore ? "Starting restoration" : "Starting upgrade" });
    try {
      await apiRef.current.request(`/v1/state/${restore ? "restore" : "upgrade"}`, "POST", { operation_id: maintenance.operation_id });
      setRecoveryRevision((current) => current + 1);
    } catch (failure) {
      acceptedOperations.current.delete(previous.operation_id);
      setMaintenance(previous);
      setError(String(failure));
    } finally { recoveryInFlight.current = false; }
  }, [maintenance]);

  const selectRecoveryWorkspace = useCallback(async (path: string) => {
    if (!apiRef.current) return;
    try {
      await apiRef.current.request("/v1/workspaces/select", "POST", { path });
      setRecoveryRevision((current) => current + 1);
    } catch (failure) { setError(String(failure)); setRecoveryRevision((current) => current + 1); }
  }, []);

  useEffect(() => {
    let disposed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    async function attach() {
      try {
        const client = await connectStudio();
        if (disposed) return;
        apiRef.current = client;
        setApi(client);
        await client.request("/v1/session/heartbeat", "POST");
        const status = await client.request<UpgradeStatus>("/v1/state/status");
        if (disposed) return;
        if (status.state !== "ready") {
          observedOperation.current = status.operation_id;
          const starting = status.state === "pending" && !status.error && acceptedOperations.current.has(status.operation_id);
          setMaintenance(starting ? { ...status, state: "running", phase: "Starting upgrade" } : status);
          setSnapshot(null);
          if (["pending", "running"].includes(status.state) && !status.error) {
            reconnectTimer = setTimeout(() => { reconnectTimer = null; void attach(); }, 500);
          }
          return;
        }
        setMaintenance(null);
        if (observedOperation.current === status.operation_id && status.backup_path) {
          setUpgradeNotice(`Studio UI state upgraded successfully. Recovery backup: ${status.backup_path}`);
        }
        observedOperation.current = null;
        acceptedOperations.current.clear();
        await client.request("/v1/session/open", "POST");
        const initial = await client.request<StudioSnapshot>("/v1/bootstrap");
        if (disposed) return;
        apiRef.current = client;
        setApi(client);
        setSnapshot(initial);
        setError(null);

        socketRef.current = client.subscribe(
          initial.seq,
          (event) => {
            if (event.kind === "state.maintenance") {
              setMaintenance(event.payload as unknown as UpgradeStatus);
              setSnapshot(null);
              setRecoveryRevision((current) => current + 1);
              return;
            }
            for (const listener of eventListeners.current) listener(event);
            setSnapshot((current) => (current ? applyEvent(current, event) : current));
            if (event.kind === "scenario.validated") {
              setValidations((current) => ({
                ...current,
                [event.entity_id]: (event.payload as unknown as { result: ValidationResult }).result,
              }));
            }
            if (event.kind === "library.refreshed" || event.kind === "workspace.selected") {
              void reload();
            }
          },
          scheduleReconnect,
          () => { if (!disposed) setLiveState("connected"); },
        );
      } catch (failure) {
        if (!disposed) {
          setLiveState("disconnected");
          setError(String(failure));
          scheduleReconnect();
        }
      }
    }

    function scheduleReconnect() {
      if (disposed || reconnectTimer) return;
      setLiveState("disconnected");
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        void attach();
      }, 1000);
    }

    void attach();
    return () => {
      disposed = true;
      socketRef.current?.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [reload, recoveryRevision]);

  useEffect(() => {
    if (!api) return;
    // Keep maintenance screens and reconnecting/minimized windows attached as well.
    const timer = setInterval(() => {
      void api.request("/v1/session/heartbeat", "POST").catch(() => undefined);
    }, 15000);
    return () => clearInterval(timer);
  }, [api]);

  return { api, snapshot, error, liveState, validations, subscribeEvents, reload, maintenance, upgradeNotice, clearUpgradeNotice, recoverState, selectRecoveryWorkspace };
}
