# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Complete bounded ES process projection from explicit canonical observations.

This is a pure projection boundary, not source admission or a metadata producer.
All file and terminal facts must come from canonical observations.
"""

from evidenceforge.events.artifact_placement import MacosRuntimeFilePlacementObservation
from evidenceforge.events.content_identity import LocalArtifactVersionRecord, canonical_native_path
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.macos_installed_file import MacosInstalledFileObservation
from evidenceforge.events.macos_process_observation import (
    MacosGUIExecResponsibilityObservation,
    MacosProcessCollectionObservation,
)
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import ESProcess
from evidenceforge.formats.macos_file_metadata import (
    es_file_from_installed_observation,
    es_file_from_runtime_record,
    es_file_from_terminal_observation,
)
from evidenceforge.formats.macos_image_security import es_image_security_fields
from evidenceforge.formats.macos_process_relationships import ESProcessRelationshipFields


def es_process_from_observations(
    relationships: ProcessRelationshipObservation,
    collection: MacosProcessCollectionObservation,
    context: ProcessContext,
    executable: (
        LocalArtifactVersionRecord
        | MacosInstalledFileObservation
        | MacosRuntimeFilePlacementObservation
    ),
    *,
    version: int,
    gui_responsibility: MacosGUIExecResponsibilityObservation | None = None,
) -> ESProcess:
    """Freeze one complete non-terminal process snapshot without field padding.

    Runtime file versions, static signatures and execution-owned security remain
    distinct inputs. The context must resolve to that exact executable version.
    Parent/responsible and collection facts must describe the same occurrence.
    A path match alone, a catalog installation or unknown attachment is insufficient.
    """
    if (
        type(relationships) is not ProcessRelationshipObservation
        or type(collection) is not MacosProcessCollectionObservation
        or type(context) is not ProcessContext
        or type(executable)
        not in {
            LocalArtifactVersionRecord,
            MacosInstalledFileObservation,
            MacosRuntimeFilePlacementObservation,
        }
    ):
        raise ValueError("ES process snapshot requires exact canonical observation types")
    relationships.__post_init__()
    relationships.parent.__post_init__()
    relationships.responsibility.__post_init__()
    collection.__post_init__()
    executable.__post_init__()
    process = relationships.parent.process
    if type(executable) is MacosRuntimeFilePlacementObservation:
        if executable.observed_at != collection.observed_at:
            raise ValueError("Runtime ES placement must describe this exact occurrence")
        loaded = executable.reference
        file_host = loaded.artifact.hostname
        file_platform = loaded.artifact.platform
        file_path = loaded.artifact.native_path
        binary = loaded.binary
        native_file = es_file_from_runtime_record(executable.placed)
    elif type(executable) is MacosInstalledFileObservation:
        binary = executable.binary
        file_host = executable.installation.hostname
        file_platform = executable.installation.platform
        file_path = executable.native_path
        if executable.observed_at != collection.observed_at:
            raise ValueError("Installed ES stat must describe this exact occurrence")
        native_file = es_file_from_installed_observation(executable)
    else:
        binary = executable.binary
        file_host = executable.artifact.hostname
        file_platform = executable.artifact.platform
        file_path = executable.artifact.native_path
        native_file = es_file_from_runtime_record(executable)
    if (
        collection.process != process
        or collection.observed_at != relationships.parent.observed_at
        or file_platform != "macos"
        or file_host != process.hostname.casefold()
        or binary is None
        or context.binary_identity != binary
        or process.executable_version != ProcessExecutableVersion.from_binary(binary)
        or canonical_native_path(file_path, "macos")
        != canonical_native_path(process.image, "macos")
    ):
        raise ValueError("ES process snapshot requires one occurrence and exact executable version")
    identity = ESProcessRelationshipFields.from_observation(
        relationships,
        version=version,
        gui_responsibility=gui_responsibility,
        boot_parent_token=collection.boot_parent_token,
    )
    security = es_image_security_fields(process, context, version=version)
    return ESProcess(
        **identity.model_dump(),
        **security,
        executable=native_file,
        is_es_client=collection.is_es_client,
        tty=(
            es_file_from_terminal_observation(collection.terminal)
            if type(collection.terminal) is MacosTerminalObservation
            else None
        ),
    )
