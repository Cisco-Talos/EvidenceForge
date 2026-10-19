# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Historical ES exec image fields from exact execution-owned arm64 facts."""

from evidenceforge.events.content_identity import BinaryReleaseIdentity, LocalArtifactBinaryIdentity
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_image import ARM64_CPU_TYPE, validate_macos_exec_image
from evidenceforge.events.process_executable import ProcessExecutableVersion


def es_exec_image_fields(
    identity: ProcessIdentity, context: ProcessContext, *, version: int
) -> dict[str, int | str]:
    """Project only admitted historical fields, preserving pre-resolution path spelling.

    This is not a full exec record or admission of macOS 26 exec. A compiled
    arm64 release without explicit subtype/exec-path knowledge is insufficient.
    """
    if type(version) is not int or version not in {6, 9}:
        raise ValueError("ES exec image projection requires an admitted historical version")
    if (
        type(identity) is not ProcessIdentity
        or type(context) is not ProcessContext
        or context.pid != identity.pid
        or context.parent_pid != identity.parent_pid
        or context.image != identity.image
        or context.command_line != identity.command_line
        or context.username != identity.principal
        or context.start_time != identity.started_at
    ):
        raise ValueError("ES exec image projection requires matching canonical execution facts")
    binary = context.binary_identity
    if type(binary) is BinaryReleaseIdentity:
        platform, architecture = binary.key.platform, binary.key.architecture
    elif type(binary) is LocalArtifactBinaryIdentity:
        platform, architecture = binary.platform, binary.architecture
    else:
        raise ValueError("ES exec image projection requires an exact resolved image")
    if (
        platform != "macos"
        or architecture != "arm64"
        or binary.mach_o_image is None
        or identity.executable_version != ProcessExecutableVersion.from_binary(binary)
    ):
        raise ValueError("ES exec image projection requires its exact loaded arm64 Mach-O version")
    facts = identity.exec_image
    validate_macos_exec_image(facts, platform)
    if facts is None:
        raise ValueError("ES exec image projection requires explicit execution metadata")
    result: dict[str, int | str] = {
        "image_cputype": ARM64_CPU_TYPE,
        "image_cpusubtype": facts.cpu_subtype,
    }
    if version == 9:
        if facts.dyld_exec_path is None:
            raise ValueError("ES v9 exec image requires its explicit pre-resolution dyld exec path")
        result["dyld_exec_path"] = facts.dyld_exec_path
    return result
