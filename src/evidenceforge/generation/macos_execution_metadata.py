# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Model-owned launch facts from frozen policy, accounts and provisioned volumes."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

from evidenceforge.config.schemas import MacosExecutionMetadataProfile
from evidenceforge.events.content_identity import BinaryReleaseIdentity, LocalArtifactBinaryIdentity
from evidenceforge.events.identity import ProcessIdentity, validate_process_arguments
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.macos_execution_directory import MacosExecutionDirectory
from evidenceforge.events.macos_file import MacosDirectoryMetadata, MacosFileTime
from evidenceforge.events.macos_runtime import MacosCodeValidationDecision, MacosImageSecurity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.generation.state_manager import (
        ActionCohortMaterializationBuilder,
        StateManager,
    )


@dataclass(frozen=True, slots=True)
class MacosLaunchMetadata:
    """Explicit launch facts fed into canonical process planning before publication."""

    environment: tuple[str, ...]
    directory: MacosExecutionDirectory
    image: MacosExecImage | None
    script: MacosExecScript | None
    image_security: MacosImageSecurity | None = None


@dataclass(frozen=True, slots=True)
class MacosPreparedExecution:
    """Canonical replacement intent plus its produced post-exec descriptor observation."""

    process: ProcessIdentity
    descriptors: MacosExecDescriptorObservation


class MacosExecutionMetadataProducer:
    """Immutable per-run directory/launch owner, with no host filesystem lookups."""

    def __init__(
        self,
        filesystem: MacosInstalledFilesystem,
        identities: IdentityDirectory,
        profile: MacosExecutionMetadataProfile,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        if (
            type(filesystem) is not MacosInstalledFilesystem
            or type(identities) is not IdentityDirectory
            or type(profile) is not MacosExecutionMetadataProfile
            or window_start.utcoffset() is None
            or window_end.utcoffset() is None
            or window_start >= window_end
        ):
            raise StateError(
                "Mac execution metadata requires exact frozen owners and a finite window"
            )
        self.profile = MacosExecutionMetadataProfile.model_validate_json(profile.model_dump_json())
        hosts = frozenset(filesystem.provisioned_hosts())
        accounts = {
            (account.host.casefold(), account.logical_name.casefold()): account
            for account in identities.macos_accounts.values()
            if account.host.casefold() in hosts
        }
        paths: dict[str, dict[str, tuple[int, int]]] = {}
        ambiguous: set[tuple[str, str]] = set()
        for account in accounts.values():
            host = account.host.casefold()
            if (
                not account.home.startswith("/")
                or ".." in PurePosixPath(account.home).parts
                or "\0" in account.home
            ):
                raise StateError("Mac execution metadata requires canonical resolved account homes")
            if account.account_name == "root":
                paths.setdefault(host, {})["/"] = (account.uid, account.gid)
            owner = account.uid, account.gid
            if (host, account.home) in ambiguous:
                continue
            existing = paths.setdefault(host, {}).setdefault(account.home, owner)
            if existing != owner:
                # Shared system homes are not user-owned directory evidence.
                paths[host].pop(account.home, None)
                ambiguous.add((host, account.home))
        born_at = window_start - timedelta(seconds=profile.directory_age_seconds)
        delta = born_at - datetime(1970, 1, 1, tzinfo=UTC)
        born = MacosFileTime(
            seconds=delta.days * 86400 + delta.seconds, nanoseconds=delta.microseconds * 1000
        )
        directories: dict[tuple[str, str], MacosDirectoryMetadata] = {}
        for host, candidates in sorted(paths.items()):
            volume = filesystem.directory_volume(host, profile.directory_first_inode)
            if volume.device == profile.terminal.device:
                raise StateError("Modeled devfs cannot reuse the installed filesystem device")
            for offset, (path, (uid, gid)) in enumerate(sorted(candidates.items())):
                inode = profile.directory_first_inode + offset
                directories[host, path] = MacosDirectoryMetadata(
                    volume_id=volume.volume_id,
                    file_object_id=f"{host}:{volume.volume_id}:{inode}",
                    device=volume.device,
                    inode=inode,
                    mode=0o040000 | profile.directory_permissions,
                    link_count=1,
                    uid=uid,
                    gid=gid,
                    special_device=0,
                    accessed=born,
                    modified=born,
                    changed=born,
                    born=born,
                    size_bytes=profile.directory_size_bytes,
                    allocated_blocks=profile.directory_allocated_blocks,
                    preferred_block_size=volume.preferred_block_size,
                    flags=0,
                    generation=0,
                )
        self._accounts = MappingProxyType(accounts)
        self._filesystem = filesystem
        self._directories = MappingProxyType(directories)
        self._known_from = born_at
        self._known_until = window_end

    def directory(self, hostname: str, path: str, at: datetime) -> MacosExecutionDirectory:
        """Observe one provisioned directory object without inferring arbitrary paths."""
        metadata = self._directories.get((hostname.casefold(), path))
        if metadata is None or not self._known_from <= at < self._known_until:
            raise StateError("Mac working directory has no provisioned facts at this time")
        return MacosExecutionDirectory(hostname, path, at, metadata)

    def launch(
        self,
        hostname: str,
        principal: str,
        *,
        at: datetime,
        requested_path: str,
        binary: BinaryReleaseIdentity | LocalArtifactBinaryIdentity | None,
        kind: Literal["user", "system"],
        script: MacosExecScript | None = None,
        validation: MacosCodeValidationDecision | None = None,
    ) -> MacosLaunchMetadata:
        """Produce an explicitly clean direct-launch environment and working directory.

        These are selected launch semantics, not reconstructed inherited values.
        Mach-O/script absence requires an exact known native binary; a shell's
        display command or file suffix never establishes direct execution.
        """
        account = self._accounts.get((hostname.casefold(), principal.casefold()))
        if (
            account is None
            or kind not in {"user", "system"}
            or (kind == "system" and account.uid != 0)
        ):
            raise StateError("Mac launch metadata requires its exact local account/profile")
        values = (
            self.profile.root_environment if kind == "system" else self.profile.user_environment
        )
        environment = tuple(
            value.format(username=account.account_name, home=account.home, shell=account.shell)
            for value in values
        )
        path = "/" if kind == "system" else account.home
        directory = self.directory(hostname, path, at)
        image = None
        if (
            type(binary) in {BinaryReleaseIdentity, LocalArtifactBinaryIdentity}
            and binary.mach_o_image is not None
            and binary.mach_o_image.architecture == "arm64"
        ):
            image = MacosExecImage(self.profile.cpu_subtype, requested_path)
            if script is None:
                script = MacosExecScript()
        return MacosLaunchMetadata(
            environment,
            directory,
            image,
            script,
            self.image_security(binary, validation=validation),
        )

    def image_security(
        self,
        binary: BinaryReleaseIdentity | LocalArtifactBinaryIdentity | None,
        *,
        validation: MacosCodeValidationDecision | None = None,
    ) -> MacosImageSecurity | None:
        """Execute the frozen modeled validation policy for an exact installed image.

        The policy explicitly selects a successful runtime outcome, independently
        of static signer metadata. It does not create missing signing facts.
        Runtime artifacts and unlisted installed images retain unknown outcomes.
        These values are synthetic model choices, never host measurements.
        """
        if validation is not None:
            if (
                type(validation) is not MacosCodeValidationDecision
                or type(binary) not in {BinaryReleaseIdentity, LocalArtifactBinaryIdentity}
                or validation.content_id != binary.content_id
                or binary.mach_o_image is None
            ):
                raise StateError(
                    "Mac validation decision must match the exact selected native image"
                )
            validation.__post_init__()
            return validation.security
        if (
            type(binary) is not BinaryReleaseIdentity
            or binary.key.platform != "macos"
            or binary.mach_o_image is None
        ):
            return None
        for rule in self.profile.code_validation:
            if (
                binary.key.product_id == rule.product_id
                and binary.key.artifact_name in rule.artifact_names
            ):
                return MacosImageSecurity(
                    rule.codesigning_flags, rule.is_platform_binary, rule.validation_category
                )
        return None

    def deployed_launch(
        self,
        hostname: str,
        principal: str,
        *,
        at: datetime,
        path: str,
        kind: Literal["user", "system"],
    ) -> MacosLaunchMetadata:
        """Produce a direct installed launch through the exact shared deployment owner."""
        return self.launch(
            hostname,
            principal,
            at=at,
            requested_path=path,
            binary=self._filesystem.deployed_binary(hostname, path, principal),
            kind=kind,
        )

    def plan_exec(
        self,
        builder: ActionCohortMaterializationBuilder,
        state: StateManager,
        process: ProcessIdentity,
        *,
        at: datetime,
        image: str,
        requested_path: str,
        arguments: tuple[str, ...],
        binary: BinaryReleaseIdentity | LocalArtifactBinaryIdentity,
        environment: tuple[str, ...] | None = None,
        script: MacosExecScript | None = None,
        validation: MacosCodeValidationDecision | None = None,
    ) -> MacosPreparedExecution:
        """Produce an exact direct image replacement through the existing State builder.

        Inheritance uses current event-time canonical state. A missing directory,
        environment, full descriptor extent or native pipe identity rejects;
        no launch default is substituted for unknown inherited execution facts.
        Publication, file retention and native collector composition remain with
        the caller's existing action transaction.
        """
        if type(process) is not ProcessIdentity or builder._manager is not state:
            raise StateError("Mac exec producer requires the exact canonical State builder")
        validate_process_arguments(arguments, command_line=shlex.join(arguments))
        known_environment = environment if environment is not None else process.environment
        current_directory = state.process_directory_at(process, event_time=at)
        table = state.process_descriptors_at(process, event_time=at)
        if known_environment is None or current_directory is None or table is None:
            raise StateError(
                "Mac exec producer requires known inherited environment, directory and descriptors"
            )
        directory = self.directory(process.hostname, current_directory.native_path, at)
        if directory.metadata.canonical_json() != current_directory.metadata.canonical_json():
            raise StateError("Mac exec working directory no longer matches its provisioned object")
        if (
            type(binary) not in {BinaryReleaseIdentity, LocalArtifactBinaryIdentity}
            or binary.mach_o_image is None
            or binary.mach_o_image.architecture != "arm64"
        ):
            raise StateError("Mac exec producer requires the exact selected native arm64 image")
        if (
            type(binary) is BinaryReleaseIdentity
            and self._filesystem.deployed_binary(process.hostname, image, process.principal)
            != binary
        ):
            raise StateError("Mac exec producer requires its exact installed image placement")
        descriptors = MacosExecDescriptorObservation.from_modeled_table(table.after_exec(at))
        after = builder.execute_process(
            process,
            image=image,
            command_line=shlex.join(arguments),
            executed_at=at,
            arguments=arguments,
            environment=known_environment,
            execution_directory=directory,
            exec_image=MacosExecImage(self.profile.cpu_subtype, requested_path),
            exec_script=script if script is not None else MacosExecScript(),
            executable_version=ProcessExecutableVersion.from_binary(binary),
            image_security=self.image_security(binary, validation=validation),
        )
        return MacosPreparedExecution(after, descriptors)
