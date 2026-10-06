import { useEffect, useRef, useState } from "react";
import type { LibraryView, StudioApi } from "./api";

export const emptyLibraryView: LibraryView = { search: "", project_id: null, show_hidden: false,
  sort: "name", expanded_groups: [], pack_kind: "packs", publisher: "", version: "", pack_source: "" };

export function useLibraryRecall(api: StudioApi | null, workspace: string | undefined,
  section: string, view: LibraryView, restore: (view: LibraryView) => void,
  onError: (message: string) => void) {
  const key = `${workspace}:${section}`;
  const [ready, setReady] = useState("");
  const callbacks = useRef({ restore, onError });
  callbacks.current = { restore, onError };
  const last = useRef("");
  const loaded = useRef("");
  const queue = useRef(Promise.resolve());
  const current = useRef({ workspace, view });
  current.current = { workspace, view };
  const value = JSON.stringify(view);
  useEffect(() => {
    if (!api || !workspace || !["scenarios", "packs"].includes(section)) return;
    let cancelled = false;
    const entry = current.current.view;
    loaded.current = "";
    void api.libraryPreferences(workspace).then((preferences) => {
      if (cancelled) return;
      const saved = preferences.remember_view !== false ? preferences[section as "scenarios" | "packs"] : undefined;
      const initial = { ...emptyLibraryView, ...saved };
      last.current = JSON.stringify(initial);
      const restored = Object.fromEntries(Object.entries(initial).map(([field, savedValue]) => {
        const name = field as keyof LibraryView;
        return [field, current.current.view[name] !== entry[name] ? current.current.view[name] : savedValue];
      })) as LibraryView;
      callbacks.current.restore(restored);
      loaded.current = key;
      setReady(key);
    }).catch((error) => { if (!cancelled) callbacks.current.onError(`Could not restore library view: ${String(error)}`); });
    return () => { cancelled = true; };
  }, [api, workspace, section, key]);
  useEffect(() => {
    if (!api || !workspace || ready !== key || loaded.current !== key || !["scenarios", "packs"].includes(section) || value === last.current) return;
    last.current = value;
    queue.current = queue.current.then(async () => {
      if (current.current.workspace !== workspace) return;
      await api.saveLibraryView(workspace, section as "scenarios" | "packs", JSON.parse(value));
    }).catch((error) => { if (current.current.workspace === workspace) callbacks.current.onError(`Could not save library view: ${String(error)}`); });
  }, [api, workspace, section, ready, key, value]);
}
