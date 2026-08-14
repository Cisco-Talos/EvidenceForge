# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SMB2/3 disk-share activity bundle."""

from __future__ import annotations

import ntpath
import posixpath
import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Literal

from evidenceforge.events.authentication import (
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    FileContext,
    FileTransferContext,
    ProcessContext,
    SmbContext,
)
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import NetworkTransactionPlan, NetworkTuple
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.storage_world import (
    CompiledStorageFile,
    CompiledStorageShare,
    StorageWorldModel,
)
from evidenceforge.models.scenario import (
    SmbActivityEventSpec,
    SmbClientLocation,
    SmbShareLocation,
    System,
    User,
)
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import parse_duration


@dataclass(frozen=True, slots=True)
class SmbActivityRequest:
    """One authored or baseline SMB activity intent."""

    spec: SmbActivityEventSpec
    actor: User
    parent_system: System
    time: datetime
    process_pid: int = -1
    process_image: str = ""
    activity_source: Literal["storyline", "baseline"] = "storyline"
    files_override: tuple[CompiledStorageFile, ...] = ()


@dataclass(frozen=True, slots=True)
class SmbActivityResult:
    """Ground-truth summary for one bounded SMB activity burst."""

    session_id: str
    tree_ids: tuple[str, ...]
    transport_uids: tuple[str, ...]
    operations: tuple[dict[str, Any], ...]
    completed_at: datetime


class SmbActivityActionBundle:
    """Compose transport/auth contracts and own SMB application semantics."""

    def __init__(self, executor: Any, request: SmbActivityRequest) -> None:
        self.executor = executor
        self.request = request
        self.world: StorageWorldModel = executor._storage_world
        self.anchor = ActionAnchor(
            family="smb_activity",
            stable_id=stable_uuid(
                "smb-activity",
                request.time,
                request.actor.username,
                request.parent_system.hostname,
                request.spec.operation,
            ),
            source=request.activity_source,
        )
        self.rng = random.Random(_stable_seed(f"smb-activity:{self.anchor.stable_id}"))

    def execute(self) -> SmbActivityResult:
        spec = self.request.spec
        composite = self._execute_composite_transfer()
        if composite is not None:
            return composite
        share_locations = self._share_locations()
        if not share_locations:
            raise ValueError("smb_activity requires at least one share location")
        primary_location = share_locations[0]
        share = self.world.share(primary_location.share)
        server = self._system(share.system)
        client_system, client_ip = self._client(server)
        self.server = server
        self.client_system = client_system
        self.mapping, self.smb_principal = self._resolve_share_leg(share)
        self.client_access = self._resolve_client_access(client_system)
        self.outcome = self._resolve_outcome(share, primary_location)
        auth_protocol = self._resolved_auth_protocol(server)
        principal_user = self.executor._user_model_for_username(self.smb_principal)
        effective_uid, effective_gid = self._effective_samba_identity(
            server,
            self.smb_principal,
        )
        selected = self._select(primary_location)
        creates_remote_copy = (
            spec.operation in {"copy", "move"}
            and not isinstance(spec.source, SmbShareLocation)
            and isinstance(spec.destination, SmbShareLocation)
        )
        if (spec.operation == "create" or creates_remote_copy) and not self.request.files_override:
            selected = (self._create_placeholder(primary_location, share),)
        if not selected and spec.outcome == "not_found" and primary_location.path is not None:
            selected = (self._missing_placeholder(primary_location, share),)
        if not selected:
            raise ValueError(f"smb_activity selected no files on {share.ref}")

        duration = self._duration(selected)
        process_plan = None
        if client_system is not None:
            first_path = selected[0].path
            source_path, destination_path = self._process_transfer_operands(
                first_path,
                share,
            )
            process_plan = self.executor.ensure_smb_client_process(
                client_system=client_system,
                actor=self.request.actor,
                server=server.hostname,
                share=share.name,
                path=first_path,
                client_path=self._client_path(first_path, share),
                local_path=self._local_path(first_path),
                source_path=source_path,
                destination_path=destination_path,
                operation=spec.operation,
                time=self.request.time,
                client_access=self.client_access,
                smb_principal=self.smb_principal,
                auth_protocol=auth_protocol,
                transfer_direction=(
                    "upload"
                    if spec.operation in {"copy", "move"}
                    and isinstance(spec.source, SmbClientLocation)
                    else "download"
                    if spec.operation in {"copy", "move"}
                    and isinstance(spec.destination, SmbClientLocation)
                    else "remote"
                    if spec.operation in {"copy", "move"}
                    else None
                ),
                preferred_pid=self.request.process_pid or -1,
                source_visible_by=self.request.time,
            )
        process = self._process_context(
            client_system,
            preferred_pid=process_plan.actor_pid if process_plan is not None else None,
        )
        transport_pid = (
            process_plan.transport_pid
            if process_plan is not None
            else process.pid
            if process is not None
            else (self.request.process_pid or -1)
        )
        transport_image = (
            process_plan.transport_image
            if process_plan is not None
            else process.image
            if process is not None
            else self.request.process_image
        )
        transport_uid = self.executor.generate_connection(
            src_ip=client_ip,
            dst_ip=server.ip,
            time=self.request.time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=duration,
            orig_bytes=self._transport_bytes(selected, write=True),
            resp_bytes=self._transport_bytes(selected, write=False),
            conn_state="SF",
            emit_dns=client_system is not None,
            source_system=client_system,
            pid=transport_pid,
            process_image=transport_image or None,
            preserve_explicit_payload=True,
            suppress_application_side_effects=True,
            suppress_source_pid_inference=self.client_access == "cifs_mount",
            parent_action_group_id=self.anchor.stable_id,
        )
        transport_plan = self.executor.dispatcher.network_plan_for(transport_uid)
        if transport_plan is None:
            raise ValueError(f"SMB transport {transport_uid!r} was not published for composition")
        if process is None and client_system is not None and transport_plan.initiating_pid > 0:
            process = self._process_context(
                client_system,
                preferred_pid=transport_plan.initiating_pid,
            )
        self.transport_start = transport_plan.started_at
        ground_truth_transport_uid = self._ground_truth_transport_uid(transport_uid)
        source_port = (
            self.executor._last_effective_connection_source_port(
                src_ip=client_ip,
                dst_ip=server.ip,
                dst_port=445,
            )
            or 0
        )
        transaction_id = self.executor._last_effective_connection_transaction_id(
            src_ip=client_ip,
            src_port=source_port,
            dst_ip=server.ip,
            dst_port=445,
        )
        auth_delay_ms = self.rng.randint(28, 96)
        tree_delay_ms = self.rng.randint(14, 88)
        auth_time = self.transport_start + timedelta(milliseconds=auth_delay_ms)
        auth_session_ref = stable_uuid(
            "smb-auth-session",
            self.anchor.stable_id,
            server.hostname,
            self.smb_principal,
            client_ip,
            source_port,
            auth_time.isoformat(),
        )
        remote_authentication_plan = None
        if self._server_platform(server) == "linux":
            remote_authentication_plan = RemoteAuthenticationPlan(
                stable_id=f"smb-remote-auth-{self.anchor.stable_id}",
                source_hostname=client_system.hostname if client_system is not None else "",
                target_hostname=server.hostname,
                logon_type=3,
                auth_protocol=auth_protocol,
                outcome="success",
                canonical_auth_time=auth_time,
                transports=(
                    RemoteAuthenticationTransportPlan(
                        role="target_service",
                        transaction_id=transaction_id,
                        tuple=NetworkTuple(
                            src_ip=transport_plan.src_ip,
                            src_port=transport_plan.src_port,
                            dst_ip=transport_plan.dst_ip,
                            dst_port=transport_plan.dst_port,
                            protocol=transport_plan.protocol,
                        ),
                        started_at=transport_plan.started_at,
                        closed_at=transport_plan.closed_at,
                        primary=True,
                    ),
                ),
                session_kind="smb",
                principal=self.smb_principal,
                account_scope="directory",
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
            )
        logon_id = self.executor.generate_logon(
            user=principal_user,
            system=server,
            time=auth_time,
            logon_type=3,
            source_ip=client_ip,
            source_system=client_system,
            source_port=source_port,
            emit_network_evidence=False,
            remote_authentication_plan=remote_authentication_plan,
            remote_authentication_transport_id=transaction_id,
            lifecycle_group_id=self.anchor.stable_id,
            session_kind="smb",
            auth_protocol=auth_protocol,
            smb_principal=self.smb_principal,
            account_scope="directory",
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        active_auth_session = self.executor.state_manager.get_session(logon_id)
        if active_auth_session is not None and active_auth_session.auth_protocol:
            auth_protocol = active_auth_session.auth_protocol
        session = self.executor.state_manager.open_smb_session(
            client_ip=client_ip,
            principal=self.smb_principal,
            server=server.hostname,
            security_policy="encrypted" if share.encryption == "required" else "standard",
            logon_id=logon_id,
            transport_uid=transport_uid,
            started_at=auth_time,
            auth_session_ref=auth_session_ref,
            auth_protocol=auth_protocol,
            account_scope="directory",
            effective_uid=effective_uid,
            effective_gid=effective_gid,
            client_access=self.client_access,
            idle_timeout=self._idle_timeout(),
            reuse=False,
        )
        tree = self.executor.state_manager.get_or_open_smb_tree(
            session.session_id,
            share.ref,
            auth_time + timedelta(milliseconds=tree_delay_ms),
        )
        net = self._application_network_plan(
            transport_plan=transport_plan,
        )
        auth = AuthContext(
            username=self.smb_principal,
            user_sid=self.executor._get_sid(self.smb_principal),
            logon_id=logon_id if self._server_platform(server) == "windows" else "",
            logon_type=3,
            source_ip=client_ip,
            source_port=source_port,
            session_kind="smb",
            auth_protocol=auth_protocol,
            smb_principal=self.smb_principal,
            account_scope="directory",
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        smb_platform_fields = self._smb_platform_fields(share, server)
        self._emit_phase(
            event_type="smb_tree_connect",
            timestamp=auth_time + timedelta(milliseconds=tree_delay_ms),
            network=net,
            server=server,
            client=client_system,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase="tree_connect",
                operation=spec.operation,
                purpose=spec.purpose,
                session_id=session.session_id,
                tree_id=tree.tree_id,
                share_ref=share.ref,
                share_name=share.name,
                share_local_path=self.world.server_local_path(share, ""),
                result="success",
                requested_access=self._requested_access(),
                **smb_platform_fields,
                encrypted=share.encryption == "required",
                audit=share.audit,
            ),
        )

        operation_truth: list[dict[str, Any]] = []
        operation_start = auth_time + timedelta(milliseconds=self.rng.randint(75, 240))
        usable_window = max(
            0.1, duration - (operation_start - self.request.time).total_seconds() - 0.2
        )
        spacing = max(0.015, usable_window / max(1, len(selected)))
        for index, file in enumerate(selected):
            operation_time = operation_start + timedelta(seconds=index * spacing)
            truth = self._execute_file_operation(
                file=file,
                share=share,
                tree_id=tree.tree_id,
                network=net,
                server=server,
                client=client_system,
                auth=auth,
                process=process,
                timestamp=operation_time,
            )
            operation_truth.append(truth)

        close_time = self.transport_start + timedelta(seconds=max(0.2, duration - 0.02))
        self.executor.generate_logoff(
            principal_user,
            server,
            close_time,
            logon_id,
            logon_type=3,
            from_storyline=True,
        )
        self.executor.state_manager.close_smb_session(session.session_id, close_time)
        return SmbActivityResult(
            session_id=session.session_id,
            tree_ids=(tree.tree_id,),
            transport_uids=(ground_truth_transport_uid,),
            operations=tuple(operation_truth),
            completed_at=close_time,
        )

    def _ground_truth_transport_uid(self, canonical_uid: str) -> str:
        """Return the emitted Zeek UID when visible, otherwise canonical truth."""
        lookup = getattr(self.executor.dispatcher, "network_identifier_for_format", None)
        if callable(lookup):
            observed_uid = lookup(canonical_uid, "zeek_conn")
            if observed_uid:
                return str(observed_uid)
        return canonical_uid

    def _execute_composite_transfer(self) -> SmbActivityResult | None:
        """Expand multi-location copy/move into bounded canonical storage legs."""

        spec = self.request.spec
        source = spec.source
        destination = spec.destination
        if spec.operation not in {"copy", "move"} or not isinstance(source, SmbShareLocation):
            return None
        if (
            spec.operation == "move"
            and isinstance(destination, SmbShareLocation)
            and destination.share.casefold() == source.share.casefold()
        ):
            return None
        if not isinstance(destination, SmbShareLocation) and spec.operation == "copy":
            return None

        selected = self._select(source)
        if not selected:
            raise ValueError(f"smb_activity selected no files on {source.share}")
        results: list[SmbActivityResult] = []
        copy_outcome = spec.outcome
        if spec.operation == "move" and not isinstance(destination, SmbShareLocation):
            copy_outcome = self._leg_outcome(source, operation="read")
        copy_spec = SmbActivityEventSpec(
            operation="copy",
            purpose=spec.purpose,
            source=source,
            destination=destination,
            outcome=copy_outcome,
            path_style=spec.path_style,
            mapping=spec.mapping,
            client=spec.client,
            client_access=spec.client_access,
            auth_protocol=spec.auth_protocol,
            smb_principal=spec.smb_principal,
        )
        if not isinstance(destination, SmbShareLocation):
            results.append(self._execute_child(copy_spec, selected, offset_ms=0))
        else:
            source_outcome = self._leg_outcome(source, operation="read")
            read_spec = SmbActivityEventSpec(
                operation="read",
                purpose=spec.purpose,
                target=source,
                outcome=source_outcome,
                path_style=spec.path_style,
                mapping=self._mapping_for_share(source.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(self._execute_child(read_spec, selected, offset_ms=0))
            if any(operation["outcome"] != "success" for operation in results[-1].operations):
                return self._combine_results(results)
            destination_files = tuple(
                file.model_copy(
                    update={
                        "file_id": stable_uuid(
                            "smb-copy-destination",
                            self.anchor.stable_id,
                            destination.share,
                            self._destination_path(destination, file.path),
                        ),
                        "share": destination.share,
                        "path": self._destination_path(destination, file.path),
                    }
                )
                for file in selected
            )
            create_spec = SmbActivityEventSpec(
                operation="create",
                purpose=spec.purpose,
                target=destination.model_copy(
                    update={"path": destination.path if len(selected) == 1 else None}
                ),
                outcome=self._leg_outcome(destination, operation="create"),
                path_style=spec.path_style,
                mapping=self._mapping_for_share(destination.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(self._execute_child(create_spec, destination_files, offset_ms=25))

        if spec.operation == "move" and any(
            operation["outcome"] != "success"
            for result in results
            for operation in result.operations
        ):
            return self._combine_results(results)
        if spec.operation == "move":
            completed_at = max(result.completed_at for result in results)
            delete_time = completed_at + sample_timing_delta(
                "smb.cross_server_delete_after_destination",
                seed_parts=(
                    self.anchor.stable_id,
                    source.share,
                    getattr(destination, "share", "client"),
                    completed_at,
                ),
            )
            delete_spec = SmbActivityEventSpec(
                operation="delete",
                purpose=spec.purpose,
                target=source,
                outcome=self._leg_outcome(source, operation="delete"),
                path_style=spec.path_style,
                mapping=self._mapping_for_share(source.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(
                self._execute_child(
                    delete_spec,
                    selected,
                    offset_ms=0,
                    execution_time=delete_time,
                )
            )
        return self._combine_results(results)

    def _execute_child(
        self,
        spec: SmbActivityEventSpec,
        files: tuple[CompiledStorageFile, ...],
        *,
        offset_ms: int,
        execution_time: datetime | None = None,
    ) -> SmbActivityResult:
        child_request = SmbActivityRequest(
            spec=spec,
            actor=self.request.actor,
            parent_system=self.request.parent_system,
            time=execution_time or self.request.time + timedelta(milliseconds=offset_ms),
            process_pid=self.request.process_pid,
            process_image=self.request.process_image,
            activity_source=self.request.activity_source,
            files_override=files,
        )
        return SmbActivityActionBundle(self.executor, child_request).execute()

    @staticmethod
    def _combine_results(results: list[SmbActivityResult]) -> SmbActivityResult:
        first = results[0]
        return SmbActivityResult(
            session_id=first.session_id,
            tree_ids=tuple(tree for result in results for tree in result.tree_ids),
            transport_uids=tuple(uid for result in results for uid in result.transport_uids),
            operations=tuple(operation for result in results for operation in result.operations),
            completed_at=max(result.completed_at for result in results),
        )

    def _destination_path(self, destination: SmbShareLocation, source_path: str) -> str:
        if destination.path is not None:
            return destination.path
        return f"Incoming\\{ntpath.basename(source_path)}"

    def _mapping_for_share(self, share_ref: str) -> str | None:
        mapping = self.world.mappings_by_id.get((self.request.spec.mapping or "").casefold())
        if mapping is None or mapping.share.casefold() != share_ref.casefold():
            return None
        return mapping.id

    def _leg_outcome(self, location: SmbShareLocation, *, operation: str) -> str:
        authored = self.request.spec.outcome
        if authored != "access_denied":
            return authored
        share = self.world.share(location.share)
        _mapping, principal = self._resolve_share_leg(share)
        return (
            "success"
            if self._has_access(
                share,
                location,
                principal_name=principal,
                operation=operation,
            )
            else "access_denied"
        )

    def _share_locations(self) -> list[SmbShareLocation]:
        spec = self.request.spec
        candidates = [spec.target, spec.source, spec.destination]
        return [candidate for candidate in candidates if isinstance(candidate, SmbShareLocation)]

    def _select(self, location: SmbShareLocation) -> tuple[CompiledStorageFile, ...]:
        if self.request.files_override:
            return self.request.files_override
        candidates = self.world.select(
            location.share,
            file_ref=location.file_ref,
            path=location.path,
            selector=location.selector,
        )
        candidates = tuple(
            file for file in candidates if self.executor.state_manager.smb_file_is_available(file)
        )
        batch = self.request.spec.batch
        if batch is None:
            if location.selector is not None:
                return candidates[:1]
            if location.file_ref is not None or location.path is not None:
                return candidates
            return candidates[:1]
        if batch.count is not None:
            count = batch.count
        elif batch.fraction is not None:
            count = max(1, round(len(candidates) * batch.fraction))
        else:
            count = len(candidates)
        return tuple(candidates[:count])

    def _create_placeholder(
        self,
        location: SmbShareLocation,
        share: CompiledStorageShare,
    ) -> CompiledStorageFile:
        path = location.path or (
            f"Incoming\\{self.request.actor.username}-{self.request.time:%Y%m%d-%H%M%S}.dat"
        )
        return CompiledStorageFile(
            file_id=stable_uuid("smb-create-placeholder", share.ref, path, self.anchor.stable_id),
            share=share.ref,
            path=path,
            size_bytes=self.rng.randint(4_096, 2_000_000),
            mime_type="application/octet-stream",
            tags=("created",),
        )

    def _missing_placeholder(
        self,
        location: SmbShareLocation,
        share: CompiledStorageShare,
    ) -> CompiledStorageFile:
        """Represent an asserted missing path without adding it to mutable state."""

        path = location.path or "missing.dat"
        return CompiledStorageFile(
            file_id=stable_uuid("smb-missing-path", share.ref, path),
            version=1,
            share=share.ref,
            path=path,
            size_bytes=0,
            mime_type="application/octet-stream",
            tags=("missing",),
        )

    def _execute_file_operation(
        self,
        *,
        file: CompiledStorageFile,
        share: CompiledStorageShare,
        tree_id: str,
        network: NetworkTransactionPlan,
        server: System,
        client: System | None,
        auth: AuthContext,
        process: ProcessContext | None,
        timestamp: datetime,
    ) -> dict[str, Any]:
        spec = self.request.spec
        result = self.outcome
        action = spec.operation
        state = file
        creates_remote_copy = (
            action in {"copy", "move"}
            and not isinstance(spec.source, SmbShareLocation)
            and isinstance(spec.destination, SmbShareLocation)
        )
        conflict_handle = None
        if result in {"access_denied", "not_found"}:
            handle = None
        elif result == "sharing_violation":
            state = self.executor.state_manager.touch_smb_file(file)
            conflict_handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp - timedelta(milliseconds=1),
                access="read",
                deny_write=True,
            )
            handle = None
        elif action == "create" or creates_remote_copy:
            state = self.executor.state_manager.create_smb_file(
                share=share.ref,
                path=file.path,
                size_bytes=file.size_bytes,
                mime_type=file.mime_type,
                timestamp=timestamp,
                tags=file.tags,
            )
            handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp,
                access="write",
            )
        else:
            state = self.executor.state_manager.touch_smb_file(file)
            access = "read" if action in {"browse", "read", "copy"} else "write"
            handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp,
                access=access,
            )
        path = state.path
        client_path = self._client_path(path, share)
        tree = self.executor.state_manager.get_smb_tree(tree_id)
        if tree is None:
            raise ValueError(f"SMB tree {tree_id!r} expired before its operation")
        common = dict(
            operation=action,
            purpose=spec.purpose,
            session_id=tree.session_id,
            tree_id=tree_id,
            share_ref=share.ref,
            share_name=share.name,
            result=result,
            requested_access=self._requested_access(),
            client_path=client_path,
            local_path=self._local_path(path),
            share_path=path,
            server_path=self.world.server_local_path(share, path),
            share_local_path=self.world.server_local_path(share, ""),
            file_id=state.file_id,
            content_version=state.version,
            handle_id=handle.handle_id if handle is not None else "",
            size_bytes=state.size_bytes,
            **self._smb_platform_fields(share, server),
            encrypted=share.encryption == "required",
            audit=share.audit,
        )
        self._emit_phase(
            event_type="smb_file_open",
            timestamp=timestamp,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(phase="open", **common),
        )
        if result != "success":
            if conflict_handle is not None:
                self.executor.state_manager.close_smb_handle(
                    conflict_handle.handle_id,
                    timestamp + timedelta(milliseconds=5),
                )
            return {
                "operation": action,
                "share": share.ref,
                "path": state.path,
                "file_id": state.file_id,
                "content_version": state.version,
                "size_bytes": state.size_bytes,
                "outcome": result,
                "fuid": None,
            }
        phase_type = {
            "browse": "smb_directory_enumeration",
            "read": "smb_file_read",
            "create": "smb_file_write",
            "update": "smb_file_write",
            "copy": "smb_file_read"
            if isinstance(spec.source, SmbShareLocation)
            else "smb_file_write",
            "move": "smb_file_write" if creates_remote_copy else "smb_file_rename",
            "delete": "smb_file_delete",
        }[action]
        phase = phase_type.removeprefix("smb_file_").removeprefix("smb_")
        file_transfer = None
        if phase in {"read", "write"} and result == "success":
            file_transfer = FileTransferContext(
                fuid=generate_stable_zeek_uid(
                    "F",
                    (
                        f"{self.anchor.stable_id}:{state.file_id}:{state.version}:"
                        f"{phase}:{'orig' if phase == 'write' else 'resp'}"
                    ),
                ),
                source="SMB",
                filename=path,
                analyzers=("MIME",),
                mime_type=state.mime_type,
                duration=max(0.001, state.size_bytes / 25_000_000),
                local_orig=client is not None,
                is_orig=phase == "write",
                seen_bytes=state.size_bytes,
                total_bytes=state.size_bytes,
            )
        previous_path = ""
        previous_client_path = ""
        previous_server_path = ""
        if action == "update":
            state = self.executor.state_manager.update_smb_file(
                state.file_id,
                size_bytes=max(1, int(state.size_bytes * self.rng.uniform(0.92, 1.15))),
            )
            common["content_version"] = state.version
            common["size_bytes"] = state.size_bytes
        elif action == "move" and not creates_remote_copy:
            destination = spec.destination
            destination_path = (
                destination.path
                if isinstance(destination, SmbShareLocation) and destination.path
                else f"Archive\\{ntpath.basename(path)}"
            )
            destination_share = (
                destination.share if isinstance(destination, SmbShareLocation) else share.ref
            )
            previous_path = path
            previous_client_path = self._client_path(path, share)
            previous_server_path = self.world.server_local_path(share, path)
            state = self.executor.state_manager.move_smb_file(
                state.file_id,
                share=destination_share,
                path=destination_path,
            )
            common["share_path"] = state.path
            common["client_path"] = self._client_path(state.path, share)
            common["server_path"] = self.world.server_local_path(share, state.path)
            common["content_version"] = state.version
        elif action == "delete":
            self.executor.state_manager.delete_smb_file(state.file_id)
        phase_rng = random.Random(
            _stable_seed(
                f"smb-phase:{self.anchor.stable_id}:{state.file_id}:{timestamp.isoformat()}"
            )
        )
        action_time = timestamp + timedelta(milliseconds=phase_rng.randint(4, 68))
        self._emit_phase(
            event_type=phase_type,
            timestamp=action_time,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase=phase,
                previous_path=previous_path,
                previous_client_path=previous_client_path,
                previous_server_path=previous_server_path,
                **common,
            ),
            file_transfer=file_transfer,
        )
        close_time = action_time + timedelta(milliseconds=phase_rng.randint(8, 135))
        if handle is not None:
            self.executor.state_manager.close_smb_handle(handle.handle_id, close_time)
        if conflict_handle is not None:
            self.executor.state_manager.close_smb_handle(conflict_handle.handle_id, close_time)
        self._emit_phase(
            event_type="smb_file_close",
            timestamp=close_time,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase="close",
                previous_path=previous_path,
                previous_client_path=previous_client_path,
                previous_server_path=previous_server_path,
                **common,
            ),
        )
        return {
            "operation": action,
            "share": share.ref,
            "path": common["share_path"],
            "file_id": state.file_id,
            "content_version": state.version,
            "size_bytes": state.size_bytes,
            "outcome": result,
            "fuid": file_transfer.fuid if file_transfer is not None else None,
        }

    def _emit_phase(
        self,
        *,
        event_type: str,
        timestamp: datetime,
        network: NetworkTransactionPlan,
        server: System,
        client: System | None,
        auth: AuthContext,
        process: ProcessContext | None,
        smb: SmbContext,
        file_transfer: FileTransferContext | None = None,
    ) -> None:
        file_context = None
        if smb.phase in {"read", "write", "delete", "rename"}:
            file_context = FileContext(
                path=smb.server_path,
                action={"write": "modify", "rename": "modify"}.get(smb.phase, smb.phase),
                pid=network.responding_pid,
            )
        event = OccurrenceBuilder(
            timestamp=timestamp,
            event_type=event_type,
            src_host=self.executor._build_host_context(client) if client is not None else None,
            dst_host=self.executor._build_host_context(server),
            auth=auth,
            process=process,
            network=network,
            file=file_context,
            file_transfer=file_transfer,
            smb=smb,
            lifecycle=ActionLifecycleContext(
                group_id=self.anchor.stable_id,
                canonical_start=self.transport_start,
                phase="dependent",
                parent_group_id=network.zeek_uid,
            ),
        )
        self.executor.dispatcher.dispatch_builder(event)

    def _application_network_plan(
        self,
        *,
        transport_plan: NetworkTransactionPlan,
    ) -> NetworkTransactionPlan:
        return replace(transport_plan, application_layer_only=True)

    def _client(self, server: System) -> tuple[System | None, str]:
        if self.request.spec.client is not None:
            return None, self.request.spec.client.ip
        if self.request.parent_system.hostname == server.hostname:
            raise ValueError("modeled SMB client must differ from the share server")
        return self.request.parent_system, self.request.parent_system.ip

    def _system(self, hostname: str) -> System:
        system = self.executor._system_for_hostname(hostname)
        if system is None:
            raise ValueError(f"unknown SMB server {hostname!r}")
        return system

    @staticmethod
    def _server_platform(system: System) -> str:
        """Return the normalized endpoint platform used by SMB projections."""

        return "windows" if "windows" in system.os.casefold() else "linux"

    def _eligible_mappings(self, share: CompiledStorageShare) -> list[Any]:
        """Return deterministic share mappings applicable to this actor/client."""

        eligible = [
            mapping
            for mapping in self.world.mappings
            if mapping.share.casefold() == share.ref.casefold()
            and (
                not mapping.users
                or self.request.actor.username.casefold()
                in {user.casefold() for user in mapping.users}
            )
            and (
                not mapping.systems
                or self.request.parent_system.hostname.casefold()
                in {system.casefold() for system in mapping.systems}
            )
        ]
        return sorted(eligible, key=lambda mapping: mapping.id.casefold())

    def _selected_mapping(self, share: CompiledStorageShare) -> Any | None:
        """Resolve an explicit or unambiguous platform presentation mapping."""

        eligible = self._eligible_mappings(share)
        mapping = self.world.mappings_by_id.get((self.request.spec.mapping or "").casefold())
        if mapping is not None and mapping.share.casefold() == share.ref.casefold():
            return mapping
        if self.request.spec.path_style in {"mapped", "mounted"} and len(eligible) == 1:
            return eligible[0]
        if self.request.spec.path_style == "auto":
            persistent = [item for item in eligible if item.lifecycle == "persistent"]
            if persistent:
                return persistent[0]
            if len(eligible) == 1:
                return eligible[0]
        return None

    def _resolve_share_leg(self, share: CompiledStorageShare) -> tuple[Any | None, str]:
        """Resolve one share leg's mapping and credential exactly as its child bundle will."""

        mapping = self._selected_mapping(share)
        return mapping, self._smb_principal_for_mapping(mapping)

    def _resolve_client_access(self, client: System | None) -> str:
        """Resolve one authored client-access mode to a concrete runtime view."""

        if client is None:
            if getattr(self.request.spec, "mapping", None) is not None:
                raise ValueError("external SMB clients cannot use storage mappings")
            if self.request.spec.client_access != "auto":
                raise ValueError("external SMB clients require client_access: auto")
            if self.request.spec.path_style not in {"auto", "unc"}:
                raise ValueError(
                    "external SMB clients require an automatic or UNC path presentation"
                )
            return "external"
        authored = self.request.spec.client_access
        path_style = self.request.spec.path_style
        client_platform = self._server_platform(client)
        if authored == "auto":
            if client_platform == "windows":
                resolved = "windows_native"
            elif self.mapping is not None and bool(getattr(self.mapping, "mount", None)):
                resolved = "cifs_mount"
            elif path_style == "mounted":
                raise ValueError(
                    "mounted SMB presentation requires an applicable storage mapping with a mount"
                )
            else:
                resolved = "smbclient"
        else:
            resolved = authored

        if resolved == "windows_native" and client_platform != "windows":
            raise ValueError("windows_native SMB access requires a Windows client")
        if resolved in {"cifs_mount", "smbclient"} and client_platform != "linux":
            raise ValueError(f"{resolved} SMB access requires a Linux client")
        allowed_path_styles = {
            "windows_native": {"auto", "unc", "mapped"},
            "cifs_mount": {"auto", "mounted"},
            "smbclient": {"auto", "unc"},
        }
        if path_style not in allowed_path_styles[resolved]:
            allowed = "/".join(sorted(allowed_path_styles[resolved]))
            raise ValueError(f"{resolved} SMB access requires one of these path styles: {allowed}")
        if resolved == "cifs_mount" and (
            self.mapping is None or not getattr(self.mapping, "mount", None)
        ):
            raise ValueError(
                "cifs_mount SMB access requires an applicable storage mapping with a mount"
            )
        return resolved

    def _resolve_smb_principal(self) -> str:
        """Keep the local actor distinct from the credential used on the share."""

        mapping = getattr(self, "mapping", None)
        if mapping is None and self.request.spec.mapping:
            mapping = self.world.mappings_by_id.get(self.request.spec.mapping.casefold())
        return self._smb_principal_for_mapping(mapping)

    def _smb_principal_for_mapping(self, mapping: Any | None) -> str:
        """Return the event or fixed credential associated with one resolved mapping."""

        if mapping is not None and getattr(mapping, "credential_mode", "per_user") == "fixed":
            fixed = str(getattr(mapping, "principal", "") or "")
            if self.request.spec.smb_principal and (
                self.request.spec.smb_principal.casefold() != fixed.casefold()
            ):
                raise ValueError(
                    "SMB activity principal conflicts with the fixed mapping credential"
                )
            return fixed
        return self.request.spec.smb_principal or self.request.actor.username

    def _resolved_auth_protocol(self, server: System) -> str:
        """Resolve authored SMB auth while preserving existing Windows defaults."""

        authored = self.request.spec.auth_protocol
        if authored != "auto":
            return authored
        # V1 Samba servers are domain members, so their automatic path uses
        # directory-backed Kerberos.  Windows retains its established
        # Negotiate selection; generate_logon records the concrete result.
        return "kerberos" if self._server_platform(server) == "linux" else ""

    def _effective_samba_identity(
        self,
        server: System,
        principal: str,
    ) -> tuple[int | None, int | None]:
        """Resolve the domain principal's host-local Unix identity for Samba."""

        if self._server_platform(server) != "linux":
            return None, None
        directory = getattr(self.executor, "identity_directory", None)
        if directory is None:
            return None, None
        account = directory.linux_account(principal, server.hostname)
        if account is None:
            account = directory.linux_account(principal)
        if account is None:
            return None, None
        return account.uid, account.gid

    def _smb_platform_fields(
        self,
        share: CompiledStorageShare,
        server: System,
    ) -> dict[str, Any]:
        """Return the independent backing and wire-advertised filesystem views."""

        volume = self.world.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
        backing = volume.filesystem
        platform = self._server_platform(server)
        advertised = share.smb_native_filesystem
        return {
            "filesystem": backing,
            "backing_filesystem": backing,
            "advertised_filesystem": advertised,
            "server_platform": platform,
            "provider": "windows" if platform == "windows" else "samba",
            "client_access": self.client_access,
        }

    def _process_context(
        self,
        client: System | None,
        *,
        preferred_pid: int | None = None,
    ) -> ProcessContext | None:
        if client is None:
            return None
        running = None
        selected_pid = preferred_pid or self.request.process_pid or -1
        if selected_pid > 0:
            running = self.executor.state_manager.get_process(
                client.hostname,
                selected_pid,
            )
        if running is None:
            candidates = [
                candidate
                for candidate in self.executor.state_manager.get_processes_on_system(
                    client.hostname
                )
                if candidate.username.casefold() == self.request.actor.username.casefold()
            ]
            candidates.sort(
                key=lambda candidate: (
                    0 if candidate.image.casefold().endswith("\\explorer.exe") else 1,
                    0
                    if candidate.image.casefold().endswith(
                        ("\\winword.exe", "\\excel.exe", "\\powerpnt.exe")
                    )
                    else 1,
                    candidate.start_time,
                    candidate.pid,
                )
            )
            running = candidates[0] if candidates else None
        if running is None:
            return None
        return ProcessContext(
            pid=running.pid,
            parent_pid=running.parent_pid,
            image=running.image,
            command_line=running.command_line,
            username=running.username,
            logon_id=running.logon_id,
            start_time=running.start_time,
        )

    def _client_path(self, path: str, share: CompiledStorageShare) -> str:
        spec = self.request.spec
        if spec.client is not None:
            return self.world.unc_path(share, path)
        if self.client_access == "cifs_mount":
            mount = str(getattr(self.mapping, "mount", "") or "")
            if mount:
                relative = path.replace("\\", "/")
                return posixpath.join(mount, relative)
        if self.client_access == "smbclient":
            relative = path.replace("\\", "/")
            return f"//{share.system}/{share.name}/{relative}"
        if spec.path_style == "unc":
            return self.world.unc_path(share, path)
        mapping = self.mapping
        drive = str(getattr(mapping, "drive", "") or "") if mapping is not None else ""
        if drive:
            return f"{drive}\\{path}"
        return self.world.unc_path(share, path)

    def _local_path(self, remote_path: str) -> str:
        source = self.request.spec.source
        destination = self.request.spec.destination
        location = source if isinstance(source, SmbClientLocation) else destination
        if not isinstance(location, SmbClientLocation):
            return ""
        client_is_linux = (
            self.client_system is not None and self._server_platform(self.client_system) == "linux"
        )
        basename = (
            posixpath.basename(remote_path.replace("\\", "/"))
            if client_is_linux
            else ntpath.basename(remote_path)
        )
        if location.path:
            if location.path.endswith(("\\", "/")):
                return f"{location.path}{basename}"
            return location.path
        if client_is_linux:
            directory = getattr(self.executor, "identity_directory", None)
            account = (
                directory.linux_account(
                    self.request.actor.username,
                    self.client_system.hostname,
                )
                if directory is not None
                else None
            )
            home = account.home if account is not None else f"/home/{self.request.actor.username}"
            return posixpath.join(home, "Downloads", basename)
        return f"C:\\Users\\{self.request.actor.username}\\Downloads\\{basename}"

    def _process_transfer_operands(
        self,
        remote_path: str,
        share: CompiledStorageShare,
    ) -> tuple[str, str]:
        """Resolve copy/move operands in the initiating client's native path view."""

        spec = self.request.spec
        if spec.operation not in {"copy", "move"}:
            return "", ""

        source_path = (
            self._local_path(remote_path)
            if isinstance(spec.source, SmbClientLocation)
            else self._client_path(remote_path, share)
        )
        if isinstance(spec.destination, SmbClientLocation):
            return source_path, self._local_path(remote_path)
        if isinstance(spec.destination, SmbShareLocation):
            destination_relative = self._destination_path(spec.destination, remote_path)
            if self.client_access == "cifs_mount":
                return source_path, self._client_path(destination_relative, share)
            return source_path, destination_relative
        return source_path, ""

    def _duration(self, files: tuple[CompiledStorageFile, ...]) -> float:
        authored = self.request.spec.batch.duration if self.request.spec.batch else None
        if authored is not None:
            return max(0.25, parse_duration(authored).total_seconds())
        total_bytes = sum(self.executor.state_manager.smb_file_size(file) for file in files)
        throughput = self.rng.uniform(6_000_000, 85_000_000)
        transfer_time = total_bytes / throughput
        setup = self.rng.uniform(0.32, 1.35)
        per_file = len(files) * self.rng.uniform(0.035, 0.22)
        dwell = {
            "interactive": self.rng.uniform(0.35, 4.5),
            "administrative": self.rng.uniform(0.15, 1.6),
            "software": self.rng.uniform(0.12, 1.2),
            "backup": self.rng.uniform(0.05, 0.5),
            "collection": self.rng.uniform(0.08, 0.9),
            "ransomware": self.rng.uniform(0.02, 0.25),
            "auto": self.rng.uniform(0.2, 2.5),
        }[self.request.spec.purpose]
        return max(2.5, min(120.0, setup + per_file + transfer_time + dwell))

    def _idle_timeout(self) -> timedelta:
        seconds = {
            "interactive": 15 * 60,
            "administrative": 8 * 60,
            "software": 20 * 60,
            "backup": 45 * 60,
            "collection": 5 * 60,
            "ransomware": 2 * 60,
            "auto": 15 * 60,
        }[self.request.spec.purpose]
        return timedelta(seconds=seconds)

    def _transport_bytes(self, files: tuple[CompiledStorageFile, ...], *, write: bool) -> int:
        operation = self.request.spec.operation
        data_bytes = sum(self.executor.state_manager.smb_file_size(file) for file in files)
        source_is_share = isinstance(self.request.spec.source, SmbShareLocation)
        destination_is_share = isinstance(self.request.spec.destination, SmbShareLocation)
        if write:
            carries_data = operation in {"create", "update"} or (
                operation in {"copy", "move"} and destination_is_share and not source_is_share
            )
        else:
            carries_data = operation == "read" or (
                operation in {"copy", "move"} and source_is_share and not destination_is_share
            )
        byte_rng = random.Random(
            _stable_seed(f"smb-wire-bytes:{self.anchor.stable_id}:{'orig' if write else 'resp'}")
        )
        if carries_data and operation == "update":
            data_bytes = int(data_bytes * byte_rng.uniform(1.16, 1.35))
        framing_bytes = byte_rng.randint(850, 2_650)
        framing_bytes += sum(byte_rng.randint(240, 1_050) for _file in files)
        return framing_bytes + (data_bytes if carries_data else 0)

    def _requested_access(self) -> str:
        """Return the access requested by the operation's remote handle."""

        spec = self.request.spec
        if spec.operation == "browse":
            return "list"
        if spec.operation in {"create", "update"}:
            return "write"
        if spec.operation == "delete":
            return "delete"
        if spec.operation == "move":
            if isinstance(spec.source, SmbShareLocation) and isinstance(
                spec.destination, SmbShareLocation
            ):
                return "rename"
            return "read" if isinstance(spec.source, SmbShareLocation) else "write"
        if spec.operation == "copy":
            return "read" if isinstance(spec.source, SmbShareLocation) else "write"
        return "read"

    def _resolve_outcome(
        self,
        share: CompiledStorageShare,
        location: SmbShareLocation,
    ) -> str:
        authored = self.request.spec.outcome
        allowed = self._has_access(share, location)
        if authored == "success" and not allowed:
            raise ValueError(
                f"SMB success is impossible: {self._resolve_smb_principal()!r} "
                f"cannot access {share.ref}"
            )
        if authored == "access_denied" and allowed:
            raise ValueError(
                f"SMB access_denied is not credible: {self._resolve_smb_principal()!r} "
                f"can access {share.ref}"
            )
        if authored == "auto":
            return "success" if allowed else "access_denied"
        return authored

    def _has_access(
        self,
        share: CompiledStorageShare,
        location: SmbShareLocation,
        *,
        principal_name: str | None = None,
        operation: str | None = None,
    ) -> bool:
        principal_name = (
            principal_name or getattr(self, "smb_principal", None) or self._resolve_smb_principal()
        )
        principal_user = self.executor._user_model_for_username(principal_name)
        username = principal_name.casefold()
        groups = {
            group.name.casefold()
            for group in self.executor._scenario_environment.groups or []
            if principal_name in group.members
        }
        groups.update(group.casefold() for group in principal_user.groups)
        principals = {username, *groups, "authenticated users", "domain users"}
        if principals.intersection(principal.casefold() for principal in share.access.deny):
            return False
        resolved_operation = operation or self.request.spec.operation
        read_access = resolved_operation in {"browse", "read"} or (
            resolved_operation == "copy" and location is self.request.spec.source
        )
        required = share.access.read if read_access else share.access.modify
        return bool(principals.intersection(principal.casefold() for principal in required))
