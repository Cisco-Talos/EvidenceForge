# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Validate the bounded authored system-job lifecycle before any generation."""

from evidenceforge.models.scenario import MacosLaunchItemEventSpec, ProcessEventSpec, Scenario
from evidenceforge.utils.platforms import platform_for_os


def persistence_problems(scenario: Scenario) -> list[tuple[str, str]]:
    """Return actionable path/message pairs using only authored modeled state."""
    problems: list[tuple[str, str]] = []
    hosts = {host.hostname: host for host in scenario.environment.systems}
    references: set[tuple[str, str, str]] = set()
    files: dict[tuple[str, str], str] = {}
    versions: dict[tuple[str, str], int] = {}
    loaded: dict[tuple[str, str], tuple[bool, str]] = {}
    for index, step in enumerate(scenario.storyline):
        for ordinal, event in enumerate(step.events):
            if isinstance(event, ProcessEventSpec) and event.process_ref is not None:
                references.add((step.system, step.actor, event.process_ref))
            if not isinstance(event, MacosLaunchItemEventSpec):
                continue
            path = f"storyline.{index}.events.{ordinal}"
            host = hosts.get(step.system)
            if (
                host is None
                or platform_for_os(host.os) != "macos"
                or host.architecture != "arm64"
                or host.type != "workstation"
            ):
                problems.append(
                    (path, "Launch-item authoring requires a modeled arm64 Mac workstation")
                )
            if (
                step.actor != "root"
                or (step.system, step.actor, event.caller_ref) not in references
            ):
                problems.append(
                    (
                        path + ".caller_ref",
                        "Launch-item stages require an earlier root process_ref on the same host",
                    )
                )
            key = (step.system, event.label)
            file_key = (step.system, event.path or "")
            if event.operation == "write":
                if event.version <= versions.get(file_key, 0):
                    problems.append(
                        (
                            path + ".version",
                            "A replacement definition requires a larger file version",
                        )
                    )
                files[file_key] = event.label
                versions[file_key] = event.version
            elif event.operation in {"bootstrap", "remove"}:
                if files.get(file_key) != event.label:
                    problems.append(
                        (
                            path + ".path",
                            "This stage requires an earlier current definition write with the same label and path",
                        )
                    )
                if event.operation == "remove":
                    files.pop(file_key, None)
                elif key in loaded:
                    problems.append(
                        (path, "Unload the currently registered job before bootstrapping it again")
                    )
                else:
                    loaded[key] = (False, path)
            elif key not in loaded:
                problems.append((path, "This stage requires an earlier loaded job"))
            elif event.operation == "activate":
                if loaded[key][0]:
                    problems.append(
                        (
                            path,
                            "Complete the running job's exit or unload before activating it again",
                        )
                    )
                loaded[key] = (True, loaded[key][1])
            elif event.operation == "exit":
                if not loaded[key][0]:
                    problems.append((path, "Completed leader exit requires an earlier activation"))
                loaded[key] = (False, loaded[key][1])
            elif event.operation == "unload":
                loaded.pop(key)
            if event.operation == "activate" and event.process_ref is not None:
                references.add((step.system, step.actor, event.process_ref))
    for index, step in enumerate(scenario.red_herrings or ()):
        if any(isinstance(event, MacosLaunchItemEventSpec) for event in step.events):
            problems.append(
                (
                    f"red_herrings.{index}",
                    "This bounded launch-item profile requires ordered storyline stages",
                )
            )
    for (_, label), (_, path) in loaded.items():
        problems.append(
            (
                path,
                f"The bounded launch-item workflow requires explicit unload for {label!r} before scenario end",
            )
        )
    return problems
