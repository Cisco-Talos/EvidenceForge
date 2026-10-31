# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Model-owned launch facts from frozen policy, accounts and provisioned volumes."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

from evidenceforge.config.schemas import MacosExecutionMetadataProfile
from evidenceforge.events.content_identity import BinaryReleaseIdentity, LocalArtifactBinaryIdentity
from evidenceforge.events.identity import (
    PosixProcessCredentials,
    ProcessIdentity,
    SessionIdentity,
    validate_process_arguments,
)
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.macos_execution_directory import MacosExecutionDirectory
from evidenceforge.events.macos_file import MacosDirectoryMetadata, MacosFileTime
from evidenceforge.events.macos_runtime import MacosCodeValidationDecision, MacosImageSecurity
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.generation.state_manager import (
        ActionCohortMaterializationBuilder,
        ProcessMaterializationPlan,
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
    credentials: PosixProcessCredentials | None = None
    responsibility: ProcessResponsibility | None = None


@dataclass(frozen=True, slots=True)
class MacosPreparedExecution:
    """Canonical replacement intent plus its produced post-exec descriptor observation."""

    process: ProcessIdentity
    descriptors: MacosExecDescriptorObservation | None


@dataclass(frozen=True, slots=True)
class MacosFinderLaunchRelationships:
    """Qualified parent/audit/responsibility only; remaining launch facts stay unknown."""

    parent: ProcessIdentity
    credentials: PosixProcessCredentials
    responsibility: ProcessResponsibility


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

    def command_completion(self, process: ProcessIdentity, at: datetime) -> PosixProcessExit | None:
        """Select declared nominal truth for an exact first command execution.

        The completion owner must separately prove a natural bounded close.
        Neither successful exec nor a matching display command establishes a result.
        Later image replacements and unspecified/frozen legacy policies stay unknown.
        """
        if (
            process.execution_ordinal != 1
            or process.arguments is None
            or not process.arguments
            or process.arguments[0] != process.image
            or process.executable_version is None
            or process.executable_version.platform != "macos"
            or process.executable_version.identity_kind != "installed_release"
            or process.exec_script != MacosExecScript()
            or (process.hostname.casefold(), process.principal.casefold()) not in self._accounts
            or not self._known_from <= process.execution_started_at < at < self._known_until
        ):
            return None
        binary = self._filesystem.deployed_binary(
            process.hostname, process.image, process.principal
        )
        if binary is None or binary.content_id != process.executable_version.content_id:
            return None
        for rule in self.profile.command_completions:
            if process.arguments == rule.arguments:
                return PosixProcessExit(exit_code=rule.exit_code)
        return None

    def directory(self, hostname: str, path: str, at: datetime) -> MacosExecutionDirectory:
        """Observe one provisioned directory object without inferring arbitrary paths."""
        metadata = self._directories.get((hostname.casefold(), path))
        if metadata is None or not self._known_from <= at < self._known_until:
            raise StateError("Mac working directory has no provisioned facts at this time")
        return MacosExecutionDirectory(hostname, path, at, metadata)

    def gui_launch_credentials(
        self,
        state: StateManager,
        hostname: str,
        principal: str,
        *,
        logon_id: str,
        at: datetime,
        credentials: PosixProcessCredentials | None,
    ) -> PosixProcessCredentials | None:
        """Bind an explicit GUI launch to its already authenticated local origin.

        The session owner allocates the origin once. A direct user launch may
        consume it; ordinary children inherit their parent's credentials. This
        does not infer audit identity from POSIX session IDs or replace a known
        foreign audit origin. Older frozen profiles/sessions retain unknowns.
        """
        if self.profile.gui_audit_origin is None or credentials is None:
            return credentials
        session = state.get_session_at(logon_id, at)
        if session is None or session.audit_origin is None:
            return credentials
        if session.session_kind != "interactive" or session.logon_type != 2:
            return credentials
        account = self._accounts.get((hostname.casefold(), principal.casefold()))
        origin = session.audit_origin
        if (
            session.system != hostname
            or session.username != principal
            or account is None
            or session.effective_uid != account.uid
            or origin.audit_uid != account.uid
            or at < origin.created_at
            or (credentials.real_uid, credentials.effective_uid) != (account.uid, account.uid)
            or (credentials.real_gid, credentials.effective_gid) != (account.gid, account.gid)
        ):
            raise StateError("Mac GUI launch requires its exact authenticated local account")
        current = credentials.audit_uid, credentials.audit_session_id
        expected = origin.audit_uid, origin.audit_session_id
        if current != (None, None) and current != expected:
            raise StateError("Mac GUI launch cannot replace a known foreign audit origin")
        return PosixProcessCredentials(
            credentials.real_uid,
            credentials.effective_uid,
            credentials.real_gid,
            credentials.effective_gid,
            *expected,
        )

    def finder_launch_relationships(
        self,
        state: StateManager,
        hostname: str,
        principal: str,
        *,
        parent_pid: int,
        logon_id: str,
        at: datetime,
        credentials: PosixProcessCredentials | None,
    ) -> MacosFinderLaunchRelationships:
        """Consume a declared regular Finder launch without inventing its exec inputs.

        The bounded reference establishes a launchd parent and self responsibility.
        Existing authenticated GUI-login authority owns the audit origin. The
        native self token is the projection of explicitly no other responsible
        lifetime; it is not a recursive reference to the new process itself.
        Environment, cwd, descriptor objects and controlling-terminal state are
        deliberately outside this relationship contract.
        """
        parent = state.get_process_identity_at(hostname, parent_pid, at)
        session = state.get_session_at(logon_id, at)
        if (
            self.profile.finder_launch_relationships != "launchd_self"
            or self.profile.gui_audit_origin != "authenticated_local_account"
            or parent is None
            or parent.pid != 1
            or parent.image != "/sbin/launchd"
            or parent.initial_image != "/sbin/launchd"
            or session is None
            or session.session_kind != "interactive"
            or session.logon_type != 2
            or session.audit_origin is None
            or not self._known_from <= at < self._known_until
        ):
            raise StateError("Finder launch requires its qualified launchd and GUI login owners")
        credentials = self.gui_launch_credentials(
            state,
            hostname,
            principal,
            logon_id=logon_id,
            at=at,
            credentials=credentials,
        )
        if (
            credentials is None
            or credentials.audit_uid is None
            or credentials.audit_session_id is None
        ):
            raise StateError("Finder launch requires its exact authenticated audit credentials")
        return MacosFinderLaunchRelationships(parent, credentials, ProcessResponsibility(None))

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
            image = MacosExecImage(self.image_cpu_subtype(binary), requested_path)
            if script is None:
                script = MacosExecScript()
        return MacosLaunchMetadata(
            environment,
            directory,
            image,
            script,
            self.image_security(binary, validation=validation),
            (
                PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0)
                if kind == "system" and self.profile.system_audit_origin == "default_unattributed"
                else PosixProcessCredentials(0, 0, 0, 0)
                if kind == "system"
                else None
            ),
            (
                ProcessResponsibility(None)
                if kind == "system" and self.profile.system_responsibility == "none"
                else None
            ),
        )

    def image_cpu_subtype(self, binary: BinaryReleaseIdentity | LocalArtifactBinaryIdentity) -> int:
        """Select an explicit artifact slice without changing the host architecture."""
        if type(binary) is BinaryReleaseIdentity:
            for rule in self.profile.code_validation:
                if (
                    binary.key.product_id == rule.product_id
                    and binary.key.artifact_name in rule.artifact_names
                    and rule.cpu_subtype is not None
                ):
                    return rule.cpu_subtype
        return self.profile.cpu_subtype

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
        Profiles select the outcome, including bounded reviewed references.
        Generation never reads host binaries or measures live validation state.
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

    def plan_fork(
        self,
        builder: ActionCohortMaterializationBuilder,
        state: StateManager,
        parent: ProcessIdentity,
        *,
        at: datetime,
        responsibility: ProcessResponsibility | None = None,
    ) -> ProcessMaterializationPlan:
        """Observe the current modeled directory for an exact canonical fork.

        The parent's launch snapshot is not a current-directory observation.
        Unknown current state stays unavailable, even if its old launch had a path.
        """
        if type(parent) is not ProcessIdentity or builder._manager is not state:
            raise StateError("Mac fork producer requires the exact canonical State builder")
        current = state.process_directory_at(parent, event_time=at)
        if current is None:
            raise StateError("Mac fork producer requires known current directory state")
        directory = self.directory(parent.hostname, current.native_path, at)
        if directory.metadata.canonical_json() != current.metadata.canonical_json():
            raise StateError("Mac fork working directory no longer matches its provisioned object")
        return builder.fork_process(
            parent, forked_at=at, execution_directory=directory, responsibility=responsibility
        )

    def login_setuid_owner(
        self, hostname: str, principal: str, binary: BinaryReleaseIdentity, at: datetime
    ) -> int:
        """Preflight the exact installed login file before allocating a startup chain."""
        if (
            self.profile.login_setuid_execution != "installed_owner"
            or type(binary) is not BinaryReleaseIdentity
            or binary.key.product_id != "apple-macos"
            or binary.key.artifact_name != "login"
        ):
            raise StateError("Mac login setuid exec requires its qualified installed Apple image")
        installed = self._filesystem.observe_image(
            hostname, "/usr/bin/login", principal, binary=binary, observed_at=at
        )
        if (
            installed.installation.scope != "machine"
            or installed.metadata.mode != 0o104555
            or installed.metadata.uid != 0
            or installed.metadata.gid != 0
        ):
            raise StateError("Mac login setuid exec requires its provisioned root-owned 04555 file")
        return installed.metadata.uid

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
        execution_directory: MacosExecutionDirectory | None = None,
        observe_descriptors: bool = True,
        gui_session: SessionIdentity | None = None,
        spawn_io: MacosSpawnIO | None = None,
    ) -> MacosPreparedExecution:
        """Produce an exact direct image replacement through the existing State builder.

        Inheritance uses current event-time canonical state. A missing directory
        or environment rejects. Native exec callers additionally require a full
        descriptor observation; fork-only startup may explicitly leave it unknown.
        No launch default substitutes for unknown inherited execution facts.
        Publication, file retention and native collector composition remain with
        the caller's existing action transaction.
        """
        if (
            type(process) is not ProcessIdentity
            or builder._manager is not state
            or type(observe_descriptors) is not bool
        ):
            raise StateError("Mac exec producer requires the exact canonical State builder")
        if gui_session is not None and (
            self.profile.finder_launch_relationships != "launchd_self"
            or environment is None
            or execution_directory is None
            or (script is not None and script.artifact_version_id is not None)
        ):
            raise StateError(
                "Finder exec requires qualified policy and explicit exec-time environment/cwd"
            )
        validate_process_arguments(arguments, command_line=shlex.join(arguments))
        known_environment = environment if environment is not None else process.environment
        current_directory = (
            execution_directory
            if execution_directory is not None
            else state.process_directory_at(process, event_time=at)
        )
        table = state.process_descriptors_at(process, event_time=at)
        if known_environment is None or current_directory is None:
            raise StateError("Mac exec producer requires known inherited environment and directory")
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
        if observe_descriptors and table is None:
            raise StateError("Mac exec producer requires known inherited descriptors")
        credentials = None
        if self.profile.login_setuid_execution == "installed_owner" and image == "/usr/bin/login":
            before = process.credentials
            if (
                type(binary) is not BinaryReleaseIdentity
                or binary.key.product_id != "apple-macos"
                or binary.key.artifact_name != "login"
                or before is None
                or before.real_uid == 0
                or before.effective_uid != before.real_uid
                or before.effective_gid != before.real_gid
                or before.audit_uid != before.real_uid
                or before.audit_session_id is None
            ):
                raise StateError(
                    "Mac login setuid exec requires its exact authenticated user input"
                )
            owner_uid = self.login_setuid_owner(process.hostname, process.principal, binary, at)
            credentials = replace(before, effective_uid=owner_uid)
        after = builder.execute_process(
            process,
            image=image,
            credentials=credentials,
            command_line=shlex.join(arguments),
            executed_at=at,
            arguments=arguments,
            environment=known_environment,
            execution_directory=directory,
            exec_image=MacosExecImage(self.image_cpu_subtype(binary), requested_path),
            exec_script=script if script is not None else MacosExecScript(),
            executable_version=ProcessExecutableVersion.from_binary(binary),
            image_security=self.image_security(binary, validation=validation),
            macos_gui_session=gui_session,
            macos_spawn_io=spawn_io,
        )
        table_after = builder.process_execution_descriptors(after)
        descriptors = (
            MacosExecDescriptorObservation.from_modeled_table(table_after)
            if observe_descriptors and table_after is not None
            else None
        )
        return MacosPreparedExecution(after, descriptors)
