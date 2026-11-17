import type { Conversation, Project } from "./api";
import { draftTitle } from "./artifactNaming";
import { ObjectMenu, type ObjectAction } from "./ObjectActions";
import { projectAssignmentAction } from "./CatalogObjectMenu";

export function DraftObjectMenu({ draft, projects, onOpen, onRename, onMove, onDelete }: {
  draft: Conversation; projects: Project[]; onOpen: () => void;
  onRename?: () => void; onMove: (id: string | null) => void; onDelete: () => void;
}) {
  const actions: ObjectAction[] = [
    { id: "open", label: "Open", group: "inspect", run: onOpen },
    ...(onRename ? [{ id: "rename", label: "Rename…", group: "manage" as const, disabled: draft.active, reason: "Finish the active authoring turn first", run: onRename }] : []),
    projectAssignmentAction(projects, onMove),
    { id: "delete", label: "Remove from Studio…", group: "remove", disabled: draft.active, reason: "Finish the active authoring turn first", run: onDelete },
  ];
  return <ObjectMenu label={`Options for ${draftTitle(draft)}`} actions={actions} />;
}
