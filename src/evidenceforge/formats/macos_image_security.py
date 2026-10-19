# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native signing projection from canonical image and runtime facts."""

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    LocalArtifactBinaryIdentity,
    MachOCodeSignature,
)
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_runtime import validate_macos_image_security


def es_image_security_fields(
    identity: ProcessIdentity, context: ProcessContext, *, version: int
) -> dict[str, str | int | bool | None]:
    """Project known signing fields without claiming client attachment or a full process.

    Runtime category is required by the bounded v10 profile and not emitted in
    the historical v6/v9 profiles. No signature, platform trust or policy verdict
    is inferred from executable paths, architecture or catalog membership.
    """
    if type(version) is not int or version not in {6, 9, 10}:
        raise ValueError("ES signing projection requires an admitted wire version")
    if (
        type(identity) is not ProcessIdentity
        or type(context) is not ProcessContext
        or (
            context.pid != identity.pid
            or context.parent_pid != identity.parent_pid
            or context.image != identity.image
            or context.command_line != identity.command_line
            or context.username != identity.principal
            or context.start_time != identity.started_at
        )
    ):
        raise ValueError("ES signing projection requires matching canonical process facts")
    binary = context.binary_identity
    if type(binary) is BinaryReleaseIdentity:
        platform = binary.key.platform
    elif type(binary) is LocalArtifactBinaryIdentity:
        platform = binary.platform
    else:
        raise ValueError("ES signing projection requires an exact resolved executable")
    security = identity.image_security
    validate_macos_image_security(security, platform)
    if platform != "macos" or security is None or binary.code_signature is None:
        raise ValueError("ES signing projection requires known static and runtime signing facts")
    if type(binary.code_signature) is not MachOCodeSignature:
        raise ValueError("ES signing projection requires an exact static signature")
    signature = MachOCodeSignature(
        binary.code_signature.signing_id,
        binary.code_signature.team_id,
        binary.code_signature.cdhash,
    )
    result: dict[str, str | int | bool | None] = dict(
        codesigning_flags=security.codesigning_flags,
        is_platform_binary=security.is_platform_binary,
        signing_id=signature.signing_id,
        team_id=signature.team_id,
        cdhash=signature.cdhash.lower(),
    )
    if version == 10:
        if security.validation_category is None:
            raise ValueError("ES v10 signing projection requires an explicit validation category")
        result["cs_validation_category"] = security.validation_category
    return result
