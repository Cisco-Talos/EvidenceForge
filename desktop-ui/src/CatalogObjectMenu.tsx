import { createContext, useContext, useState } from "react";
import type { CatalogItem, PackReview, StudioApi } from "./api";
import { ArtifactLifecycle } from "./ArtifactLifecycle";
import { ObjectMenu, type ObjectAction } from "./ObjectActions";
import { artifactTitle } from "./artifactNaming";

interface CatalogActionEnvironment {
  api: StudioApi;
  actions: (item: CatalogItem) => ObjectAction[];
  onChanged: () => Promise<void>;
  onOpenArtifact: (path: string) => Promise<void>;
  onVersions: (item: CatalogItem) => void;
  busy: boolean;
  onError: (message: string) => void;
  environmentRefreshing?: string | null;
  environmentRefreshVersion?: (item: CatalogItem) => number;
  packReview?: (item: CatalogItem) => PackReview | null;
  onPackReview?: (item: CatalogItem, review: PackReview) => void;
}

export const CatalogActionContext = createContext<CatalogActionEnvironment | null>(null);

/** Library, workspace and dependency menus share one artifact action definition. */
export function CatalogObjectMenu({ item, fallbackActions = [], label, actionIds }: {
  item: CatalogItem; fallbackActions?: ObjectAction[]; label?: string; actionIds?: readonly string[];
}) {
  const environment = useContext(CatalogActionContext);
  const [inspected, setInspected] = useState(false);
  const menuLabel = label || `Options for ${artifactTitle(item)}${item.kind !== "scenario" && item.version ? ` ${item.version}` : ""}`;
  const scoped = (actions: ObjectAction[]) => actionIds ? actions.filter((action) => actionIds.includes(action.id)) : actions;
  if (!environment) return <ObjectMenu label={menuLabel} actions={scoped(fallbackActions)} />;
  const base = environment.actions(item);
  const missing = base.find((action) => action.id === "recover-source");
  if (missing) return <ObjectMenu label={menuLabel} actions={scoped(base)} />;
  return <ArtifactLifecycle item={item} api={environment.api} inspect={inspected} disabled={environment.busy} onError={environment.onError} onChanged={environment.onChanged} onOpen={environment.onOpenArtifact} onProperties={() => environment.onVersions(item)} renderActions={(lifecycle) => <ObjectMenu label={menuLabel} actions={scoped([...base, ...lifecycle.filter((action) => !base.some((entry) => entry.id === action.id))])} onOpenChange={(open) => { if (open) { setInspected(true); if (item.kind !== "scenario") void environment.api.request<PackReview>(`/v1/packs/${item.id}/review`).then((review) => environment.onPackReview?.(item, review)).catch((error) => environment.onError(String(error))); } }} />} />;
}

export function projectAssignmentAction(projects: { id: string; name: string }[], onMove: (id: string | null) => void, onNewProject?: () => void): ObjectAction {
  return { id: "move", label: "Move to project", group: "organize", children: [
    { id: "ungrouped", label: "Ungrouped", group: "organize", run: () => onMove(null) },
    ...projects.map((project): ObjectAction => ({ id: project.id, label: project.name, group: "organize", run: () => onMove(project.id) })),
    ...(onNewProject ? [{ id: "new-project", label: "New project…", group: "organize" as const, run: onNewProject }] : []),
  ] };
}
