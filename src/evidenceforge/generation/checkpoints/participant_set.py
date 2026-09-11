"""Production assembly for explicit incremental checkpoint participants."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from evidenceforge.generation.process_runtime_cache import EmailArtifactManifestSpool

from .activity_head import ActivityGeneratorStateParticipant
from .application_channel_head import ApplicationChannelRegistryParticipant
from .artifact_registry_head import LocalArtifactVersionRegistryParticipant
from .bash_command_memory import BashCommandMemoryParticipant
from .cryptographic_material_head import CryptographicMaterialParticipant
from .deferred_source_spool import DeferredSourceSpoolParticipant
from .dispatcher_observation_head import DispatcherObservationParticipant
from .emitter_spools import EmitterSpoolParticipant
from .engine_head import GenerationEngineParticipant
from .http_channel_head import HttpApplicationChannelParticipant
from .intent_ledger_head import IntentExecutionLedgerParticipant
from .lifecycle_authority_head import GeneratorLifecycleAuthorityParticipant
from .lifecycle_head import LifecycleRegistryParticipant
from .network_runtime_head import NetworkTransactionRuntimeParticipant
from .network_visibility_head import NetworkVisibilityParticipant
from .participants import IncrementalCheckpointParticipant
from .process_runtime_head import ProcessRuntimeCachesParticipant
from .proxy_channel_head import ExplicitProxyChannelParticipant
from .proxy_emitter_head import ProxyEmitterParticipant
from .rdp_head import RdpSessionManagerParticipant
from .rng import GenerationRngParticipant
from .smb_channel_head import SmbApplicationChannelParticipant
from .snort_spool import SnortSpoolParticipant
from .source_timing_head import SourceTimingPlannerParticipant
from .spools import ImmutableSpoolFilesParticipant
from .sqlite_spool import SQLiteSpoolParticipant
from .ssh_channel_head import SshApplicationChannelParticipant
from .state_manager_head import StateManagerParticipant
from .syslog_spool import SyslogSpoolParticipant
from .timing_runtime_head import TimingRuntimeParticipant

if TYPE_CHECKING:
    from evidenceforge.generation.engine import GenerationEngine


def _email_manifest_participant(engine: GenerationEngine) -> SQLiteSpoolParticipant | None:
    """Create the optional email-manifest adapter before its first append."""

    generator = engine.activity_generator
    if generator is None:
        raise RuntimeError("checkpoint participants require an initialized activity generator")
    email = getattr(generator._scenario_environment, "email", None)
    artifacts = getattr(email, "artifacts", None)
    if artifacts is None or artifacts.mode == "none":
        return None
    spool = getattr(generator, "_email_artifact_manifest_spool", None)
    if spool is None:
        spool = EmailArtifactManifestSpool(generator._artifacts_manifest_path)
        generator._email_artifact_manifest_spool = spool
    if type(spool) is not EmailArtifactManifestSpool:
        raise RuntimeError("email artifact manifest checkpoint owner changed")
    return SQLiteSpoolParticipant(
        owner="email-artifact-manifest-spool",
        connection=spool.checkpoint_connection,
        tables=("manifest_rows",),
        restore_complete=spool.restore_checkpoint_state,
    )


def _email_artifact_files_participant(
    engine: GenerationEngine,
) -> ImmutableSpoolFilesParticipant | None:
    """Create the immutable adapter for materialized MIME artifacts."""

    generator = engine.activity_generator
    if generator is None:
        raise RuntimeError("checkpoint participants require an initialized activity generator")
    email = getattr(generator._scenario_environment, "email", None)
    artifacts = getattr(email, "artifacts", None)
    if artifacts is None or artifacts.mode == "none":
        return None
    artifact_directory = generator._email_artifact_dir

    def source_files() -> dict[str, Path]:
        try:
            paths = tuple(artifact_directory.iterdir())
        except FileNotFoundError:
            return {}
        discovered: dict[str, Path] = {}
        for path in paths:
            if path.is_dir():
                raise RuntimeError(f"email artifact directory contains a nested directory: {path}")
            discovered[path.name] = path
        return discovered

    return ImmutableSpoolFilesParticipant(
        owner="email-artifact-files",
        source_files=source_files,
        restore_path=lambda name: artifact_directory / name,
    )


def production_checkpoint_participants(
    engine: GenerationEngine,
) -> tuple[IncrementalCheckpointParticipant, ...]:
    """Return the stable explicit participant set for one initialized engine."""

    generator = engine.activity_generator
    timing = engine.timing_runtime
    source_timing = engine.source_timing_planner
    if generator is None or timing is None or source_timing is None:
        raise RuntimeError("checkpoint participants require a fully initialized engine")
    for emitter in engine.emitters.values():
        emitter.enable_incremental_checkpointing()
    participants: list[IncrementalCheckpointParticipant] = [
        StateManagerParticipant(engine.state_manager),
        TimingRuntimeParticipant(timing),
        SourceTimingPlannerParticipant(source_timing),
        LifecycleRegistryParticipant(engine.lifecycle_authority.registry),
        GeneratorLifecycleAuthorityParticipant(
            engine.lifecycle_authority,
            systems=tuple(engine.scenario.environment.systems),
        ),
        ApplicationChannelRegistryParticipant(engine.application_channel_registry),
        CryptographicMaterialParticipant(generator._cryptographic_material_registry),
        NetworkTransactionRuntimeParticipant(generator._network_transaction_runtime),
        NetworkVisibilityParticipant(engine.dispatcher.visibility_engine),
        HttpApplicationChannelParticipant(generator._http_channel_manager),
        ExplicitProxyChannelParticipant(generator._proxy_channel_manager),
        SshApplicationChannelParticipant(generator._ssh_channel_manager),
        SmbApplicationChannelParticipant(generator._smb_channel_manager),
        RdpSessionManagerParticipant(generator._rdp_session_manager),
        IntentExecutionLedgerParticipant(engine.intent_execution_ledger),
        DispatcherObservationParticipant(engine.dispatcher),
        ActivityGeneratorStateParticipant(generator),
        BashCommandMemoryParticipant(),
        EmitterSpoolParticipant(emitters=engine.emitters, output_root=engine.output_dir),
        GenerationEngineParticipant(engine),
        GenerationRngParticipant(),
    ]
    for format_name in ("windows_event_security", "windows_event_sysmon"):
        emitter = engine.emitters.get(format_name)
        if emitter is not None:
            participants.append(
                DeferredSourceSpoolParticipant(format_name=format_name, emitter=emitter)
            )
    snort = engine.emitters.get("snort_alert")
    if snort is not None:
        participants.append(SnortSpoolParticipant(snort))
    syslog = engine.emitters.get("syslog")
    if syslog is not None:
        participants.append(SyslogSpoolParticipant(syslog))
    proxy = engine.emitters.get("proxy_access")
    if proxy is not None:
        participants.append(ProxyEmitterParticipant(proxy))
    process_caches = getattr(generator, "_production_process_runtime_caches", None)
    if process_caches is not None:
        participants.append(ProcessRuntimeCachesParticipant(process_caches))
    artifact_registry = getattr(engine.dispatcher, "local_artifact_registry", None)
    if artifact_registry is not None:
        participants.append(LocalArtifactVersionRegistryParticipant(artifact_registry))
    email_participant = _email_manifest_participant(engine)
    if email_participant is not None:
        participants.append(email_participant)
    email_files_participant = _email_artifact_files_participant(engine)
    if email_files_participant is not None:
        participants.append(email_files_participant)
    owners = [participant.checkpoint_owner for participant in participants]
    if len(owners) != len(set(owners)):
        raise RuntimeError("production checkpoint participant owners are not unique")
    return tuple(participants)


__all__ = ["production_checkpoint_participants"]
