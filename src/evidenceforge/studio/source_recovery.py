"""Conservative recovery of moved authored scenarios; source files are never changed."""

from pathlib import Path

from evidenceforge.studio.store import CatalogItem, StudioStore


def source_busy(store: StudioStore, items: list[CatalogItem]) -> bool:
    """Protect chats and pending/running jobs while associations change."""
    ids = {item.id for item in items}
    paths = {str(path) for item in items for path in store.source_paths(item)}
    workspace = items[0].workspace
    if any(chat.active and chat.item_id in ids for chat in store.conversations(workspace)):
        return True
    jobs = store.job_payloads(workspace)
    generations = {job["id"] for job in jobs if job.get("scenario") in paths}
    return any(
        job["status"] in {"running", "queued", "paused"}
        and (job.get("scenario") in paths or job.get("generation_id") in generations)
        for job in jobs
    )


def compatible_registration(old: CatalogItem, target: CatalogItem) -> bool:
    """Avoid silently resolving conflicting project or folder assignments."""
    return not (
        old.project_id
        and target.project_id
        and old.project_id != target.project_id
        or old.folder
        and target.folder
        and old.folder != target.folder
    )


def reconcile_sources(store: StudioStore, workspace: Path) -> list[CatalogItem]:
    """Relink only one missing draft to one live draft with the same indexed UUID."""
    groups: dict[str, list[CatalogItem]] = {}
    for item in store.items(workspace, "scenario"):
        identity = store.draft_identity(item)
        if identity:
            groups.setdefault(identity, []).append(item)
    moved: list[CatalogItem] = []
    for members in groups.values():
        missing = [item for item in members if not item.path.exists()]
        live = [item for item in members if item.path.is_file() and not item.path.is_symlink()]
        if (
            len(missing) != 1
            or len(live) != 1
            or not live[0].path.is_relative_to(workspace.resolve())
        ):
            continue
        old, target = missing[0], live[0]
        if not compatible_registration(old, target) or source_busy(store, members):
            continue
        try:
            moved.append(store.relink_scenario(old, target))
        except (OSError, ValueError):
            # An external edit or another catalog mutation requires a fresh scan.
            continue
    return moved
