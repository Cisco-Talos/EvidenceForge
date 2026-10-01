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
} from "./api";

export interface StudioState {
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
  } else if (event.kind === "codex.health") {
    next.codex_health = event.payload as unknown as CodexHealth;
  }
  return next;
}

export function useStudio(): StudioState {
  const [api, setApi] = useState<StudioApi | null>(null);
  const [snapshot, setSnapshot] = useState<StudioSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [validations, setValidations] = useState<Record<string, ValidationResult>>({});
  const socketRef = useRef<WebSocket | null>(null);
  const apiRef = useRef<StudioApi | null>(null);
  const eventListeners = useRef(new Set<(event: StudioEvent) => void>());

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

  useEffect(() => {
    let disposed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    async function attach() {
      try {
        const client = await connectStudio();
        if (disposed) return;
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
  }, [reload]);

  return { api, snapshot, error, liveState, validations, subscribeEvents, reload };
}
