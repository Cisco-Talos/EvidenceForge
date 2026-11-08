# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read only new second-host references; emit closed shape/relationship findings.

Raw references and derived stat comparisons stay on the authorized reference Mac.
This standalone Python 3.9+ checker never launches a collector or workload and
never enables native generation. Local tests supply invented records only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType


def _support() -> ModuleType:
    path = Path(__file__).with_name("filesystem_reference.py")
    if not path.exists():
        path = Path(__file__).with_name("macos_remote_filesystem_reference.py")
    spec = importlib.util.spec_from_file_location("_eforge_remote_filesystem_support", path)
    if spec is None or spec.loader is None:
        raise ValueError("CODE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


support = _support()
TOP = frozenset(
    (
        "schema_version",
        "version",
        "event_type",
        "action_type",
        "action",
        "time",
        "mach_time",
        "seq_num",
        "global_seq_num",
        "thread",
        "process",
        "event",
    )
)
PROCESS = frozenset(
    (
        "audit_token",
        "parent_audit_token",
        "responsible_audit_token",
        "ppid",
        "original_ppid",
        "group_id",
        "session_id",
        "codesigning_flags",
        "is_platform_binary",
        "is_es_client",
        "executable",
        "tty",
        "start_time",
        "signing_id",
        "team_id",
        "cdhash",
        "cs_validation_category",
    )
)
STAT = frozenset(
    (
        "st_dev",
        "st_mode",
        "st_nlink",
        "st_ino",
        "st_uid",
        "st_gid",
        "st_rdev",
        "st_atimespec",
        "st_mtimespec",
        "st_ctimespec",
        "st_birthtimespec",
        "st_size",
        "st_blocks",
        "st_blksize",
        "st_flags",
        "st_gen",
    )
)
PAYLOAD = {
    "create": {"destination_type", "destination", "acl"},
    "close": {"target", "modified", "was_mapped_writable"},
    "rename": {"source", "destination_type", "destination"},
    "unlink": {"target", "parent_dir"},
    "exit": {"stat"},
}


def native_time(value: object, digits: int) -> bool:
    """Check exact source timestamp spelling without exporting the timestamp."""
    if type(value) is not str or not re.fullmatch(
        rf"[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}\.[0-9]{{{digits}}}Z",
        value,
    ):
        return False
    try:
        # Python 3.9 accepts only 3/6 fractional digits in fromisoformat. The
        # source spelling is checked above; validate its calendar separately
        # without normalizing or truncating the saved nanosecond evidence.
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


def file_shape(value: object) -> bool:
    """Verify the declared file/stat shape; retain every original value privately."""
    if type(value) is not dict or set(value) != {"path", "path_truncated", "stat"}:
        return False
    data = value["stat"]
    if type(data) is not dict or set(data) != STAT or type(value["path"]) is not str:
        return False
    if type(value["path_truncated"]) is not bool:
        return False
    for name, item in data.items():
        if name.endswith("timespec"):
            if not native_time(item, 9):
                return False
        elif type(item) is not int:
            return False
    return True


def row_shape(row: dict) -> bool:
    """Check the common v11 envelope and public per-family property layouts."""
    if set(row) != TOP or row.get("schema_version") != 1 or row.get("version") != 11:
        return False
    for name in (
        "schema_version",
        "version",
        "event_type",
        "action_type",
        "mach_time",
        "seq_num",
        "global_seq_num",
    ):
        if type(row[name]) is not int or row[name] < 0:
            return False
    if row["action_type"] != 1 or not native_time(row["time"], 9):
        return False
    if row["action"] != {"result": {"result_type": 0, "result": {"auth": 0}}}:
        return False
    if type(row["thread"]) is not dict or set(row["thread"]) != {"thread_id"}:
        return False
    if type(row["thread"]["thread_id"]) is not int or row["thread"]["thread_id"] < 0:
        return False
    process = row["process"]
    if type(process) is not dict or set(process) != PROCESS:
        return False
    for name in ("audit_token", "parent_audit_token", "responsible_audit_token"):
        if type(process[name]) is not dict or support.token_words(process[name]) is None:
            return False
    if not file_shape(process["executable"]) or not native_time(process["start_time"], 6):
        return False
    if process["tty"] is not None and not file_shape(process["tty"]):
        return False
    for name in (
        "ppid",
        "original_ppid",
        "group_id",
        "session_id",
        "codesigning_flags",
        "cs_validation_category",
    ):
        if type(process[name]) is not int or process[name] < 0:
            return False
    if any(type(process[name]) is not bool for name in ("is_platform_binary", "is_es_client")):
        return False
    if any(
        process[name] is not None and type(process[name]) is not str
        for name in ("signing_id", "team_id")
    ):
        return False
    if type(process["cdhash"]) is not str or not re.fullmatch(
        r"[0-9a-fA-F]{40}", process["cdhash"]
    ):
        return False
    event = row["event"]
    if type(event) is not dict or len(event) != 1:
        return False
    family = next(iter(event))
    if family not in PAYLOAD or row["event_type"] != support.EVENT_TYPES[family]:
        return False
    payload = event[family]
    if type(payload) is not dict or set(payload) != PAYLOAD[family]:
        return False
    if family == "exit":
        return type(payload["stat"]) is int
    if family == "close":
        return file_shape(payload["target"]) and all(
            type(payload[name]) is bool for name in ("modified", "was_mapped_writable")
        )
    if family == "unlink":
        return file_shape(payload["target"]) and file_shape(payload["parent_dir"])
    if family == "rename" and not file_shape(payload["source"]):
        return False
    destination = payload["destination"]
    if type(destination) is not dict or type(payload["destination_type"]) is not int:
        return False
    if payload["destination_type"] == 0:
        return (
            set(destination) == {"existing_file"}
            and file_shape(destination["existing_file"])
            and (family != "create" or payload["acl"] is None)
        )
    if payload["destination_type"] == 1 and family == "rename":
        new = destination.get("new_path")
        return (
            set(destination) == {"new_path"}
            and type(new) is dict
            and set(new) == {"dir", "filename"}
            and file_shape(new["dir"])
            and type(new["filename"]) is str
        )
    return False


def control_key(value: object) -> tuple[int, int] | None:
    """Return an own-probe file key only for local equality comparisons."""
    if type(value) is not dict:
        return None
    if type(value.get("dev")) is not int or type(value.get("ino")) is not int:
        return None
    return value["dev"], value["ino"]


def stat_phase(native: object, before: object, after: object) -> str:
    """Compare only private stat facts; return a closed phase label, never values."""
    if type(native) is not dict or type(before) is not dict:
        return "UNMEASURED"

    def snapshot(control: object) -> tuple | None:
        if type(control) is not dict or any(
            type(control.get(key)) is not int
            for key in ("dev", "ino", "size", "mtime_sec", "mtime_nsec", "ctime_sec", "ctime_nsec")
        ):
            return None
        return tuple(
            control[key]
            for key in ("dev", "ino", "size", "mtime_sec", "mtime_nsec", "ctime_sec", "ctime_nsec")
        )

    def stamp(value: object) -> tuple[int, int] | None:
        if type(value) is not str:
            return None
        match = re.fullmatch(r"([0-9-]+T[0-9:]+)\.([0-9]{9})Z", value)
        if match is None:
            return None
        # Keep this standalone reference tool compatible with remote Python 3.9.
        zero_offset = timezone(timedelta(0))
        try:
            moment = datetime.fromisoformat(match[1]).replace(tzinfo=zero_offset)
        except ValueError:
            return None
        delta = moment - datetime(1970, 1, 1, tzinfo=zero_offset)
        return delta.days * 86400 + delta.seconds, int(match[2])

    mtime, ctime = stamp(native.get("st_mtimespec")), stamp(native.get("st_ctimespec"))
    old, new = snapshot(before), snapshot(after)
    if mtime is None or ctime is None or old is None:
        return "UNMEASURED"
    observed = (native.get("st_dev"), native.get("st_ino"), native.get("st_size"), *mtime, *ctime)
    matches_before, matches_after = observed == old, new is not None and observed == new
    if matches_before and matches_after:
        return "UNCHANGED"
    return "BEFORE" if matches_before else "AFTER" if matches_after else "UNMATCHED"


def directory_stat_phases(controls: list[dict], rows: list[dict]) -> dict:
    """Classify the finite parent/source stat matrix without publishing raw facts."""
    steps = {item.get("step"): item for item in controls if item.get("kind") == "step"}
    result = {
        key: {phase: 0 for phase in ("BEFORE", "AFTER", "UNCHANGED", "UNMATCHED", "UNMEASURED")}
        for key in ("rename_new_parent", "rename_source", "unlink_parent", "unlink_source")
    }
    for row in rows:
        event = row.get("event", {})
        if "rename" in event:
            payload = event["rename"]
            step = steps.get(2 if payload.get("destination_type") == 1 else 5, {})
            source = payload.get("source", {})
            if support.file_key(source) != control_key(step.get("before")):
                continue
            phase = stat_phase(source.get("stat"), step.get("before"), step.get("after"))
            result["rename_source"][phase] += 1
            parent = payload.get("destination", {}).get("new_path", {}).get("dir")
            if type(parent) is dict:
                phase = stat_phase(
                    parent.get("stat"), step.get("parent_before"), step.get("parent_after")
                )
                result["rename_new_parent"][phase] += 1
        elif "unlink" in event:
            payload = event["unlink"]
            step = next(
                (
                    steps.get(index, {})
                    for index in (6, 7)
                    if support.file_key(payload.get("target"))
                    == control_key(steps.get(index, {}).get("before"))
                ),
                None,
            )
            if step is None:
                continue
            for name, key, before, after in (
                ("unlink_parent", "parent_dir", "parent_before", "parent_after"),
                ("unlink_source", "target", "before", "after"),
            ):
                phase = stat_phase(
                    payload.get(key, {}).get("stat"), step.get(before), step.get(after)
                )
                result[name][phase] += 1
    return result


def shape_diagnostics(rows: list[dict]) -> dict:
    """Locate a shape mismatch using predeclared technical labels only."""
    by_family = {name: [item for item in rows if name in item.get("event", {})] for name in PAYLOAD}

    def time_shape(value: object) -> str:
        if type(value) is not str:
            return "NON_STRING"
        for digits, label in ((9, "NANOSECONDS"), (6, "MICROSECONDS"), (3, "MILLISECONDS")):
            if native_time(value, digits):
                return label
            if re.fullmatch(
                rf"[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}\.[0-9]{{{digits}}}[+-]00:00",
                value,
            ):
                return label + "_UTC_OFFSET"
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
            return "WHOLE_SECONDS"
        return "OTHER_STRING"

    def time_structure(value: object) -> dict:
        if type(value) is not str:
            return {"string": False}
        fraction = re.search(r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.([0-9]+)", value)
        return {
            "string": True,
            "date_prefix": bool(re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}", value)),
            "t_separator": len(value) > 10 and value[10] == "T",
            "space_separator": len(value) > 10 and value[10] == " ",
            "fraction_digits": min(len(fraction[1]), 32) if fraction else 0,
            "z_suffix": value.endswith("Z"),
            "offset_colon": bool(re.search(r"[+-][0-9]{2}:[0-9]{2}$", value)),
            "offset_compact": bool(re.search(r"[+-][0-9]{4}$", value)),
            "space_before_offset": bool(re.search(r" [+-][0-9]{2}:?[0-9]{2}$", value)),
        }

    files = [item.get("process", {}).get("executable", {}) for item in rows]
    return {
        "envelope_keys": all(set(item) == TOP for item in rows),
        "process_keys": all(set(item.get("process", {})) == PROCESS for item in rows),
        "process_file_shape": all(
            file_shape(item.get("process", {}).get("executable")) for item in rows
        ),
        "process_file_keys": all(
            type(item) is dict and set(item) == {"path", "path_truncated", "stat"} for item in files
        ),
        "process_stat_keys": all(
            type(item.get("stat")) is dict and set(item["stat"]) == STAT for item in files
        ),
        "event_time_representation": sorted({time_shape(item.get("time")) for item in rows}),
        "event_time_structure": time_structure(rows[0].get("time")) if rows else {},
        "stat_time_structure": time_structure(files[0].get("stat", {}).get("st_mtimespec"))
        if files
        else {},
        "stat_time_representation": sorted(
            {
                time_shape(value)
                for item in files
                for name, value in item.get("stat", {}).items()
                if name.endswith("timespec")
            }
        ),
        "event_time_shape": all(native_time(item.get("time"), 9) for item in rows),
        "process_time_shape": all(
            native_time(item.get("process", {}).get("start_time"), 6) for item in rows
        ),
        "action_shape": all(
            item.get("action") == {"result": {"result_type": 0, "result": {"auth": 0}}}
            for item in rows
        ),
        "family_row_shapes": {
            name: all(row_shape(item) for item in group) for name, group in by_family.items()
        },
        "payload_keys": {
            name: all(set(item["event"][name]) == PAYLOAD[name] for item in group)
            for name, group in by_family.items()
        },
        "payload_extra_field_counts": {
            name: sorted({len(set(item["event"][name]) - PAYLOAD[name]) for item in group})
            for name, group in by_family.items()
        },
    }


def relationships(controls: list[dict], rows: list[dict], image: str, root: str) -> dict:
    """Report only fixed conclusions about shapes, controls and file relationships."""
    ready = [item for item in controls if item.get("kind") == "ready"]
    steps = [item for item in controls if item.get("kind") == "step"]
    valid = (
        len(ready) == 1
        and [item.get("step") for item in steps] == list(range(8))
        and all(item.get("ok") is True for item in steps)
        and sum(item.get("kind") == "done" for item in controls) == 1
    )
    if not valid:
        raise ValueError("CONTROLS")
    tracker = support.Tracker(ready[0], image, root)
    families = {family: [] for family in support.FAMILIES}
    for row in rows:
        event = row.get("event", {})
        if type(event) is dict and len(event) == 1 and next(iter(event)) in families:
            families[next(iter(event))].append(row)
    result = {
        "controls_complete": True,
        "v11_shapes_match": all(row_shape(row) for row in rows),
        "actors_match_control": all(tracker.owns_process(row.get("process")) for row in rows),
        "create_identities_match": False,
        "close_identities_match": False,
        "rename_identities_match": False,
        "unlink_identities_match": False,
        "normal_exit_matched": len(families["exit"]) == 1
        and families["exit"][0]["event"]["exit"].get("stat") == 0,
        "read_close_modified": "UNMEASURED",
        "write_closes_modified": "UNMEASURED",
        "create_size_phase": [],
        "replacement_destination_identity": "UNMEASURED",
        "unlink_link_phase": [],
        "mapped_writable_seen": False,
    }
    create_pairs = (("alpha", 0), ("victim", 3), ("candidate", 4))
    identity_matches = []
    for name, step in create_pairs:
        candidates = [
            item["event"]["create"]["destination"].get("existing_file")
            for item in families["create"]
            if item["event"]["create"].get("destination_type") == 0
        ]
        targets = [
            item
            for item in candidates
            if type(item) is dict and item.get("path") == root + "/" + name
        ]
        identity_matches.append(
            len(targets) == 1 and support.file_key(targets[0]) == control_key(steps[step]["after"])
        )
        if len(targets) == 1:
            size = targets[0]["stat"].get("st_size")
            result["create_size_phase"].append(
                "EMPTY_BEFORE_WRITE" if size == 0 else "POST_WRITE" if size == 3 else "OTHER"
            )
    result["create_identities_match"] = all(identity_matches)
    close_matches = []
    for name, step, count in (("alpha", 0, 2), ("victim", 3, 1), ("candidate", 4, 1)):
        targets = [
            item["event"]["close"]["target"]
            for item in families["close"]
            if item["event"]["close"].get("target", {}).get("path") == root + "/" + name
        ]
        close_matches.append(
            len(targets) == count
            and all(support.file_key(item) == control_key(steps[step]["after"]) for item in targets)
        )
    result["close_identities_match"] = all(close_matches)
    rename_matches = []
    for name, step in (("alpha", 2), ("candidate", 5)):
        targets = [
            item["event"]["rename"]
            for item in families["rename"]
            if item["event"]["rename"].get("source", {}).get("path") == root + "/" + name
        ]
        same = (
            len(targets) == 1
            and support.file_key(targets[0]["source"]) == control_key(steps[step]["before"])
            and control_key(steps[step]["before"]) == control_key(steps[step]["after"])
        )
        rename_matches.append(same)
        if len(targets) == 1 and step == 5:
            key = support.file_key(targets[0]["destination"].get("existing_file"))
            result["replacement_destination_identity"] = (
                "REPLACED_FILE"
                if key == control_key(steps[step]["replaced"])
                else "RENAMED_SOURCE"
                if key == control_key(steps[step]["after"])
                else "NEW_PATH"
                if targets[0].get("destination_type") == 1
                else "OTHER"
            )
    result["rename_identities_match"] = all(rename_matches)
    unlink_matches = []
    for name, step in (("fresh", 6), ("victim", 7)):
        targets = [
            item["event"]["unlink"]["target"]
            for item in families["unlink"]
            if item["event"]["unlink"].get("target", {}).get("path") == root + "/" + name
        ]
        unlink_matches.append(
            len(targets) == 1 and support.file_key(targets[0]) == control_key(steps[step]["before"])
        )
        if len(targets) == 1:
            links = targets[0]["stat"].get("st_nlink")
            result["unlink_link_phase"].append(
                "BEFORE_REMOVAL" if links == 1 else "AFTER_REMOVAL" if links == 0 else "OTHER"
            )
    result["unlink_identities_match"] = all(unlink_matches)
    alpha_closes = sorted(
        [
            item
            for item in families["close"]
            if item["event"]["close"].get("target", {}).get("path") == root + "/alpha"
        ],
        key=lambda item: item["mach_time"],
    )
    if len(alpha_closes) == 2:
        result["write_closes_modified"] = (
            "MODIFIED"
            if alpha_closes[0]["event"]["close"].get("modified") is True
            else "UNMODIFIED"
        )
        result["read_close_modified"] = (
            "MODIFIED"
            if alpha_closes[1]["event"]["close"].get("modified") is True
            else "UNMODIFIED"
        )
    result["mapped_writable_seen"] = any(
        item["event"]["close"].get("was_mapped_writable") is True for item in families["close"]
    )
    return result


def checked_file(path: Path, limit: int) -> None:
    """Admit only bounded, private, regular files from the new run directory."""
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size > limit
    ):
        raise ValueError("ARTIFACT")


def review(work: Path) -> dict:
    """Authenticate one immutable capture before reading its native records."""
    for name, limit in (
        ("provenance.json", 65536),
        ("controls.json", 65536),
        ("REPORT.json", 65536),
        ("native.ndjson", support.MAX_RETAINED_BYTES),
    ):
        checked_file(work / name, limit)
    provenance = support.decode((work / "provenance.json").read_bytes())
    original = support.decode((work / "REPORT.json").read_bytes())
    if original != provenance.get("report"):
        raise ValueError("PROVENANCE")
    for name in ("native.ndjson", "controls.json"):
        matches = [item for item in provenance["files"] if item.get("name") == name]
        if len(matches) != 1 or matches[0].get("sha256") != support.digest(work / name):
            raise ValueError("PROVENANCE")
    if (
        original.get("error") != "NONE"
        or not original.get("collector_ready")
        or not original.get("controls_complete")
        or not original.get("cleanup")
    ):
        raise ValueError("CAPTURE_CONTROL")
    controls = json.loads((work / "controls.json").read_bytes())
    if (
        type(controls) is not list
        or len(controls) > 20
        or any(type(item) is not dict for item in controls)
    ):
        raise ValueError("CONTROLS")
    rows = []
    with (work / "native.ndjson").open("rb") as source:
        for line in source:
            if len(rows) >= support.MAX_RETAINED_RECORDS:
                raise ValueError("RECORD_LIMIT")
            rows.append(support.decode(line))
    result = relationships(
        controls, rows, str(work.parent / "filesystem-probe"), str(work / "scratch")
    )
    result["shape_diagnostics"] = shape_diagnostics(rows)
    result["directory_stat_phases"] = directory_stat_phases(controls, rows)
    result["stream_complete_control"] = (
        original.get("stream_sequence_gaps") == 0
        and original.get("stream_sequence_reordered") is False
    )
    result["reference_admission"] = "NOT_EVALUATED"
    return result


def main() -> None:
    """Report fixed findings from at most the two predeclared new runs."""
    kit = Path(__file__).resolve().parent
    runs = sorted(path for path in kit.iterdir() if path.name.startswith("filesystem-run-"))
    reports = []
    for work in runs[:2]:
        try:
            info = work.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise ValueError("DIRECTORY")
            reports.append(review(work))
        except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
            reports.append(
                {"error": "REFERENCE_CHECK_FAILED", "reference_admission": "NOT_EVALUATED"}
            )
    print(
        json.dumps(
            {"schema_version": 1, "runs": reports, "run_limit_exceeded": len(runs) > 2},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
