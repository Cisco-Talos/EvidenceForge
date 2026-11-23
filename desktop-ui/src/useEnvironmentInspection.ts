import { useEffect, useState } from "react";
import type { CatalogItem, EnvironmentReport, StudioApi } from "./api";
import type { RequestState } from "./RequestFeedback";

/** Environment and Network share one inspection for the same inputs. */
export function useEnvironmentInspection({ api, item, enabled, dependencyFingerprint, refreshVersion = 0 }: {
  api: StudioApi; item: CatalogItem; enabled: boolean; dependencyFingerprint?: string; refreshVersion?: number;
}) {
  const [refresh, setRefresh] = useState(0);
  const requestKey = JSON.stringify([item.id, item.source_sha256, dependencyFingerprint, refreshVersion, refresh]);
  const [response, setResponse] = useState<{ key: string; report?: EnvironmentReport } & RequestState>();
  const current = enabled && response?.key === requestKey ? response : undefined;
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    void api.request<EnvironmentReport>(`/v1/scenarios/${item.id}/environment`, "GET", undefined, 180000)
      .then((report) => {
        if (!cancelled) setResponse({ key: requestKey, report, pending: false, completedAt: Date.now() / 1000 });
      })
      .catch((failure) => {
        if (!cancelled) setResponse({ key: requestKey, pending: false, error: String(failure) });
      });
    return () => { cancelled = true; };
  }, [api, item.id, enabled, requestKey]);
  return {
    requestKey,
    report: current?.report,
    pending: enabled && !current,
    error: current?.error,
    completedAt: current?.completedAt,
    refresh: () => setRefresh((value) => value + 1),
  };
}
