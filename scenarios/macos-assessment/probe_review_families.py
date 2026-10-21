"""Check endpoint population, embedded command time and shared path identity."""

import argparse
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field


class ReviewProbe(BaseModel, extra="forbid"):
    journal_paths: int = 0
    history_matches: int = 0
    mac_self_image_creates: int = 0
    gui_max_instances: dict[str, int] = Field(default_factory=dict)
    ocsp_duration_range_seconds: float | None = None
    failures: list[str] = Field(default_factory=list)


def probe(data: Path) -> ReviewProbe:
    """Read only the explicitly authorized synthetic data tree."""
    report = ReviewProbe()
    for path in sorted(data.rglob("ecar.json")):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        births = {
            row["objectID"]: row | row.get("properties", {})
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "CREATE"
        }
        is_macos = (path.parent / "zsh_history").is_dir() or (
            path.parent / "macos_endpoint_security.ndjson"
        ).exists()
        journal_ids: set[str] = set()
        native = path.with_name("syslog.log")
        if native.exists():
            journal_ids.update(
                re.findall(r"/log/journal/([0-9a-f]{32})(?:[/\s]|$)", native.read_text())
            )
        for row in rows:
            if row["object"] != "FILE":
                continue
            target = row.get("properties", {}).get("file_path", "")
            match = re.search(r"/log/journal/([^/]+)/", target)
            if match:
                report.journal_paths += 1
                identity = match.group(1)
                if re.fullmatch(r"[0-9a-f]{32}", identity) is None:
                    report.failures.append(
                        f"{path.parent.name}: invalid journal machine ID {identity}"
                    )
                journal_ids.add(identity)
            actor = births.get(row.get("actorID"))
            if actor and is_macos and row["action"] == "CREATE":
                if target == actor.get("image_path"):
                    report.mac_self_image_creates += 1
                    report.failures.append(
                        f"{path.parent.name}: execution creates its own image {target}"
                    )
        if len(journal_ids) > 1:
            report.failures.append(
                f"{path.parent.name}: journal sources disagree on machine identity"
            )

        for history in sorted(path.parent.glob("zsh_history/*.zsh_history")):
            username = history.name.removesuffix(".zsh_history")
            for line in history.read_text().splitlines():
                match = re.match(r": (\d+):\d+;(.*)", line)
                if match is None:
                    continue
                at, command = int(match.group(1)), match.group(2)
                candidates = [
                    birth
                    for birth in births.values()
                    if birth.get("command_line") == command and birth.get("principal") == username
                ]
                if candidates:
                    report.history_matches += 1
                    difference = min(abs(birth["timestamp_ms"] / 1000 - at) for birth in candidates)
                    if difference > 2:
                        report.failures.append(
                            f"{path.parent.name}: embedded history start differs by {difference:.3f}s"
                        )

        # These main executables have the benchmark's explicit session-instance
        # policy. Helpers and deliberately separate sessions do not share a key.
        mains = {"Code", "idea", "sublime_text", "Postman", "dbeaver", "Terminal"}
        live: dict[tuple[str, str, str], set[str]] = {}
        for row in sorted(rows, key=lambda item: item["timestamp_ms"]):
            if row["object"] != "PROCESS" or row["action"] not in {"CREATE", "TERMINATE"}:
                continue
            birth = births.get(row["objectID"])
            if birth is None:
                continue
            image = birth.get("image_path", "")
            if image.rsplit("/", 1)[-1] not in mains or ".app/Contents/MacOS/" not in image:
                continue
            key = (birth.get("principal", ""), birth.get("logon_id", ""), image)
            objects = live.setdefault(key, set())
            if row["action"] == "CREATE":
                objects.add(row["objectID"])
            else:
                objects.discard(row["objectID"])
            metric = f"{path.parent.name}:{key[0]}:{key[1]}:{image}"
            report.gui_max_instances[metric] = max(
                report.gui_max_instances.get(metric, 0), len(objects)
            )
        for key, maximum in report.gui_max_instances.items():
            if key.startswith(path.parent.name + ":") and maximum > 1:
                report.failures.append(f"{key}: {maximum} concurrent main processes")

    durations: list[float] = []
    for http in sorted(data.rglob("http.json")):
        connections = {
            row["uid"]: row
            for row in (
                json.loads(line) for line in http.with_name("conn.json").read_text().splitlines()
            )
        }
        for line in http.read_text().splitlines():
            row = json.loads(line)
            if "ocsp" in row.get("host", "").lower() and row["uid"] in connections:
                duration = connections[row["uid"]].get("duration")
                if duration is not None:
                    durations.append(duration)
    if durations:
        report.ocsp_duration_range_seconds = max(durations) - min(durations)
    return report


def main() -> None:
    """Persist findings without printing synthetic evidence rows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.data.resolve(strict=True))
    args.output.write_text(json.dumps(report.model_dump(), indent=2) + "\n")
    print(
        f"failures={len(report.failures)} history_matches={report.history_matches} journal_paths={report.journal_paths}"
    )
    raise SystemExit(bool(report.failures))


if __name__ == "__main__":
    main()
