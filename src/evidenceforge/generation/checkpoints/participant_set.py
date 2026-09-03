"""Production assembly for explicit incremental checkpoint participants."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evidenceforge.generation.process_runtime_cache import EmailArtifactManifestSpool

from .activity_head import ActivityGeneratorStateParticipant
from .application_channel_head import ApplicationChannelRegistryParticipant
from .artifact_registry_head import LocalArtifactVersionRegistryParticipant
from .cryptographic_material_head import CryptographicMaterialParticipant
from .emitter_spools import EmitterSpoolParticipant
from .engine_head import GenerationEngineParticipant
from .http_channel_head import HttpApplicationChannelParticipant
from .intent_ledger_head import IntentExecutionLedgerParticipant
from .lifecycle_head import LifecycleRegistryParticipant
from .network_runtime_head import NetworkTransactionRuntimeParticipant
from .participants import IncrementalCheckpointParticipant
from .process_runtime_head import ProcessRuntimeCachesParticipant
from .proxy_channel_head import ExplicitProxyChannelParticipant
from .rdp_head import RdpSessionManagerParticipant
from .rng import GenerationRngParticipant
from .smb_channel_head import SmbApplicationChannelParticipant
from .source_timing_head import SourceTimingPlannerParticipant
from .sqlite_spool import SQLiteSpoolParticipant
from .ssh_channel_head import SshApplicationChannelParticipant
from .state_manager_head import StateManagerParticipant
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
        ApplicationChannelRegistryParticipant(engine.application_channel_registry),
        CryptographicMaterialParticipant(generator._cryptographic_material_registry),
        NetworkTransactionRuntimeParticipant(generator._network_transaction_runtime),
        HttpApplicationChannelParticipant(generator._http_channel_manager),
        ExplicitProxyChannelParticipant(generator._proxy_channel_manager),
        SshApplicationChannelParticipant(generator._ssh_channel_manager),
        SmbApplicationChannelParticipant(generator._smb_channel_manager),
        RdpSessionManagerParticipant(generator._rdp_session_manager),
        IntentExecutionLedgerParticipant(engine.intent_execution_ledger),
        ActivityGeneratorStateParticipant(generator),
        EmitterSpoolParticipant(emitters=engine.emitters, output_root=engine.output_dir),
        GenerationEngineParticipant(engine),
        GenerationRngParticipant(),
    ]
    process_caches = getattr(generator, "_production_process_runtime_caches", None)
    if process_caches is not None:
        participants.append(ProcessRuntimeCachesParticipant(process_caches))
    artifact_registry = getattr(engine.dispatcher, "local_artifact_registry", None)
    if artifact_registry is not None:
        participants.append(LocalArtifactVersionRegistryParticipant(artifact_registry))
    email_participant = _email_manifest_participant(engine)
    if email_participant is not None:
        participants.append(email_participant)
    owners = [participant.checkpoint_owner for participant in participants]
    if len(owners) != len(set(owners)):
        raise RuntimeError("production checkpoint participant owners are not unique")
    return tuple(participants)


__all__ = ["production_checkpoint_participants"]
