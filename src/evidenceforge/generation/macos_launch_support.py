# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free launch qualification from exact deployment and frozen policy.

Catalog presence is installation intent. This query additionally proves the
binary metadata and canonical launch mechanism needed for native process truth.
It consumes no randomness and never consults selected emitters or host files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from evidenceforge.config.schemas import MacosExecutionMetadataProfile
from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.generation.activity.process_helpers import _macos_process_uses_shell

if TYPE_CHECKING:
    from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
    from evidenceforge.models.scenario import Scenario


class MacosLaunchSupport(BaseModel):
    """One exact executable's launch mechanism and explicit missing facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mechanism: Literal["finder", "terminal", "command", "helper"] | None
    issues: tuple[str, ...] = ()


class MacosLaunchIssue(BaseModel):
    """A reachable installed application that cannot satisfy native launch truth."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    username: str
    image: str
    issues: tuple[str, ...]


def modeled_image_security(
    profile: MacosExecutionMetadataProfile, binary: BinaryReleaseIdentity
) -> MacosImageSecurity | None:
    """Resolve the single declared runtime policy for this exact installed artifact."""
    if binary.key.platform != "macos" or binary.mach_o_image is None:
        return None
    for rule in profile.code_validation:
        if (
            rule.product_id == binary.key.product_id
            and binary.key.artifact_name in rule.artifact_names
        ):
            return MacosImageSecurity(
                rule.codesigning_flags, rule.is_platform_binary, rule.validation_category
            )
    return None


def resolve_macos_launch_support(
    registry: DeploymentContentRegistry,
    profile: MacosExecutionMetadataProfile,
    hostname: str,
    username: str,
    image: str,
) -> MacosLaunchSupport:
    """Resolve installed identity and policy without admitting a process birth."""
    issues: list[str] = []
    binary = registry.resolve_binary(hostname, image, "macos", principal=username)
    if binary is None:
        issues.append("executable_not_installed")
    else:
        if binary.mach_o_image is None:
            issues.append("mach_o_image_unknown")
        if binary.code_signature is None:
            issues.append("signing_unknown")
        elif binary.code_signature.entitlements is None:
            issues.append("entitlements_unknown")
        if modeled_image_security(profile, binary) is None:
            issues.append("image_security_unknown")

    mechanism: Literal["finder", "terminal", "command", "helper"] | None = "command"
    if ".app/Contents/MacOS/" in image and not _macos_process_uses_shell(image):
        mechanism = None
        if image in profile.finder_launch_images:
            mechanism = "finder"
            if (
                profile.finder_launch_execution != "xpcproxy_app_exec"
                or profile.finder_launch_relationships != "launchd_self"
            ):
                issues.append("gui_launch_policy_unknown")
            if not any(entry.image == image for entry in profile.finder_applications):
                issues.append("bundle_identifier_unknown")
        elif any(entry.image == image for entry in profile.browser_helpers):
            mechanism = "helper"
        else:
            user_profile = registry.user_profile_for(hostname, username, "macos")
            for terminal in profile.terminal_startups:
                assignment = (
                    registry.user_application_assignment_for_application(
                        user_profile.profile_id, terminal.application_id
                    )
                    if user_profile is not None
                    else None
                )
                if (
                    assignment is not None
                    and registry.application_executable_for_assignment(assignment) == image
                ):
                    mechanism = "terminal"
                    break
        if mechanism is None:
            issues.append("launch_mechanism_unknown")
    return MacosLaunchSupport(mechanism=mechanism, issues=tuple(issues))


def macos_launch_issues(
    scenario: Scenario,
    registry: DeploymentContentRegistry,
    profile: MacosExecutionMetadataProfile,
) -> tuple[MacosLaunchIssue, ...]:
    """Check reachable baseline apps and installed authored targets before sampling."""
    from evidenceforge.generation.activity.helpers import _get_os_category

    candidates: set[tuple[str, str, str]] = set()
    hosts = {
        host.hostname: host
        for host in scenario.environment.systems
        if _get_os_category(host.os) == "macos"
    }
    for hostname in hosts:
        for user in scenario.environment.users:
            user_profile = registry.user_profile_for(hostname, user.username, "macos")
            if user_profile is None or not user.enabled:
                continue
            for assignment in registry.iter_user_application_assignments_for_profile(
                user_profile.profile_id
            ):
                descriptor = registry.application_descriptor_for_assignment(assignment)
                image = registry.application_executable_for_assignment(assignment)
                if (
                    descriptor is not None
                    and image is not None
                    and descriptor.command_templates
                    and {"user_app", "browser", "code", "office", "build", "query"}.intersection(
                        descriptor.categories
                    )
                ):
                    candidates.add((hostname, user.username, image))
    for step in (*scenario.storyline, *scenario.red_herrings):
        if step.system not in hosts:
            continue
        for event in step.events:
            if event.type != "process" or event.outcome == "policy_refused":
                continue
            if registry.resolve_binary(
                step.system, event.process_name, "macos", principal=step.actor
            ):
                candidates.add((step.system, step.actor, event.process_name))
    findings: list[MacosLaunchIssue] = []
    for hostname, username, image in sorted(candidates):
        support = resolve_macos_launch_support(registry, profile, hostname, username, image)
        if support.issues:
            findings.append(
                MacosLaunchIssue(
                    hostname=hostname, username=username, image=image, issues=support.issues
                )
            )
    return tuple(findings)
