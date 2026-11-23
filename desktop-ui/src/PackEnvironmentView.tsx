import { useEffect, useState } from "react";
import type { CatalogItem, NetworkChatContext, PackTopology, StudioApi, StudioEvent } from "./api";
import { NetworkDiagram } from "./NetworkDiagram";
import { RequestFeedback } from "./RequestFeedback";

export function PackEnvironmentView({ item, api, subscribeEvents, onChanged, onAsk }: {
  item: CatalogItem; api: StudioApi;
  subscribeEvents: (listener: (event: StudioEvent) => void) => () => void;
  onChanged: () => Promise<void>;
  onAsk?: (context: NetworkChatContext) => Promise<void>;
}) {
  const [refresh, setRefresh] = useState(0);
  const [refreshingLibrary, setRefreshingLibrary] = useState(false);
  const requestKey = JSON.stringify([item.id, item.source_sha256, refresh]);
  const [inspection, setInspection] = useState<{ key: string; report?: PackTopology; error?: string }>();
  const current = inspection?.key === requestKey ? inspection : undefined;

  useEffect(() => subscribeEvents((event) => {
    if (event.entity_id === item.id && event.kind === "assets.updated") {
      setRefresh((value) => value + 1);
    }
  }), [item.id, subscribeEvents]);

  useEffect(() => {
    let cancelled = false;
    void api.request<PackTopology>(`/v1/packs/${item.id}/topology`, "GET", undefined, 180000)
      .then((report) => {
        if (cancelled) return;
        if (report.source_sha256 !== item.source_sha256) {
          setInspection({ key: requestKey, error: "The pack changed during inspection. Reopen it from the library to load the current revision." });
        } else {
          setInspection({ key: requestKey, report });
        }
      })
      .catch((failure) => {
        if (!cancelled) setInspection({ key: requestKey, error: String(failure) });
      });
    return () => { cancelled = true; };
  }, [api, item.id, item.source_sha256, requestKey]);

  async function refreshEnvironment() {
    setRefreshingLibrary(true);
    try {
      await onChanged();
    } catch (failure) {
      setInspection({ key: requestKey, error: String(failure) });
      return;
    } finally {
      setRefreshingLibrary(false);
    }
    setRefresh((value) => value + 1);
  }

  const pending = refreshingLibrary || !current;
  const refreshAction = <button type="button" className="button-quiet" disabled={pending} onClick={() => void refreshEnvironment()}>Refresh environment</button>;
  const description = `Organization pack fragment · ${item.version || "Draft"}`;
  return !pending && current?.report
    ? <NetworkDiagram key={current.report.digest} graph={current.report.topology} revision={current.report.digest}
      description={description} actions={refreshAction} onAsk={onAsk} />
    : <div className="diagram-unavailable">
      {refreshAction}
      <RequestFeedback pending={pending} label="Reading organization environment…" error={current?.error} />
    </div>;
}
