"""Explicit successful-journal publications, independent of timing and failure handling."""

UPGRADE_JOURNALS = tuple(
    f"journal.upgrade.{state}.{step}.{publication}.{side}_write"
    for state, step in (
        ("pending", 0),
        ("running", 0),
        ("running", 1),
        ("running", 2),
        ("running", 3),
        ("ready", 5),
    )
    for publication in ("package", "pointer")
    for side in ("before", "after")
)
RESTORE_JOURNALS = tuple(
    f"journal.restore.{state}.{step}.{publication}.{side}_write"
    for state, step in (
        ("running", 0),
        ("running", 1),
        ("running", 2),
        ("running", 3),
        ("restored", 5),
    )
    for publication in ("package", "pointer")
    for side in ("before", "after")
)
