# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared preflight for the public native Mac completeness policy."""

from datetime import datetime

from evidenceforge.events.collection_policy import CollectionCapability
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario


def requires_complete_macos_processes(scenario: Scenario, formats: frozenset[str]) -> bool:
    """Default to completeness when native ES output is actually requested."""
    return scenario.macos_process_coverage == "complete" or (
        scenario.macos_process_coverage is None and "macos_endpoint_security" in formats
    )


def validate_complete_collection(
    scenario: Scenario,
    deployment: CompiledCollectionDeployment,
    formats: frozenset[str],
    start: datetime,
    end: datetime,
) -> None:
    """Reject known exclusions before any simulated activity is accepted."""
    if not requires_complete_macos_processes(scenario, formats):
        return
    for system in scenario.environment.systems:
        if _get_os_category(system.os) != "macos":
            continue
        source = deployment.source_by_instance(
            exact_source_instance_id("macos_endpoint_security", system.hostname)
        )
        reason = ""
        if "macos_endpoint_security" not in formats or source is None:
            reason = "native macos_endpoint_security output is not selected"
        elif not source.policy.enabled:
            reason = "the native source is disabled"
        elif not source.policy.capabilities & CollectionCapability.PROCESS:
            reason = "the native source excludes process evidence"
        elif source.policy.missingness_for("macos_endpoint_security") != 0:
            reason = "the native source requests collection loss"
        else:
            frontier = start
            for window in source.policy.windows:
                if window.start is not None and window.start > frontier:
                    break
                if window.end is None:
                    frontier = end
                    break
                frontier = max(frontier, window.end)
                if frontier >= end:
                    break
            if frontier < end:
                reason = "native collection does not cover the entire simulation window"
        if reason:
            raise StateError(
                f"Complete macOS process coverage on {system.hostname} is unavailable: {reason}. "
                "Select lossless process collection for the full window, or explicitly set "
                "macos_process_coverage: partial for a diagnostic run without this guarantee."
            )
