# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Complete bounded ES process projection from explicit canonical observations.

This is a pure projection boundary, not source admission or a metadata producer.
Installed executable stat and terminal-device profiles remain separate work.
"""

from evidenceforge.events.content_identity import LocalArtifactVersionRecord, canonical_native_path
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import ESProcess
from evidenceforge.formats.macos_file_metadata import es_file_from_runtime_record
from evidenceforge.formats.macos_image_security import es_image_security_fields
from evidenceforge.formats.macos_process_relationships import ESProcessRelationshipFields


def es_process_from_observations(
    relationships: ProcessRelationshipObservation,
    collection: MacosProcessCollectionObservation,
    context: ProcessContext,
    executable: LocalArtifactVersionRecord,
    *,
    version: int,
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
        or type(executable) is not LocalArtifactVersionRecord
    ):
        raise ValueError("ES process snapshot requires exact canonical observation types")
    relationships.__post_init__()
    relationships.parent.__post_init__()
    relationships.responsibility.__post_init__()
    collection.__post_init__()
    executable.__post_init__()
    process = relationships.parent.process
    if (
        collection.process != process
        or collection.observed_at != relationships.parent.observed_at
        or executable.artifact.platform != "macos"
        or executable.artifact.hostname != process.hostname.casefold()
        or executable.binary is None
        or context.binary_identity != executable.binary
        or canonical_native_path(executable.artifact.native_path, "macos")
        != canonical_native_path(process.image, "macos")
    ):
        raise ValueError("ES process snapshot requires one occurrence and exact executable version")
    identity = ESProcessRelationshipFields.from_observation(relationships, version=version)
    security = es_image_security_fields(process, context, version=version)
    return ESProcess(
        **identity.model_dump(),
        **security,
        executable=es_file_from_runtime_record(executable),
        is_es_client=collection.is_es_client,
        tty=None,  # Explicitly known absence, validated by the observation contract.
    )
