# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Produce modeled installed-file facts from frozen scenario/deployment inputs.

This is synthetic provisioning, not discovery. It models single-link immutable
regular files, one host-local volume and explicit dense allocation throughout
the supplied collection/warmup window. Runtime replacements and terminal devices
remain with their separate owners. No file is read from the generator host.
"""

import math
import random
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from statistics import NormalDist

from evidenceforge.config.schemas import MacosInstalledFileProfile
from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    SoftwareInstallationIdentity,
)
from evidenceforge.events.macos_file import MacosFileTime
from evidenceforge.generation.activity.macos_installed_files import (
    load_macos_installed_file_profile,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_installed_filesystem import (
    MacosInstalledFileSpec,
    MacosInstalledFilesystem,
    MacosInstalledVolumeSpec,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.platforms import platform_for_os
from evidenceforge.utils.rng import DEFAULT_GENERATION_SEED, _stable_seed, generation_seed_scope


@dataclass(frozen=True, slots=True)
class MacosUnprovisionedInstallation:
    """A deployed file whose owner is unknown; other evidence can still proceed."""

    installation_id: str
    principal: str
    hostname: str


@dataclass(frozen=True, slots=True)
class MacosInstalledProvisioning:
    """One immutable engine-owned provider and explicit unsupported-owner findings."""

    filesystem: MacosInstalledFilesystem
    provisioned_files: int
    unavailable: tuple[MacosUnprovisionedInstallation, ...]


def _time(value: datetime, rng: random.Random) -> MacosFileTime:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return MacosFileTime(
        seconds=delta.days * 86400 + delta.seconds,
        nanoseconds=delta.microseconds * 1000 + rng.randrange(1000),
    )


def _release_size(binary: BinaryReleaseIdentity, profile: MacosInstalledFileProfile) -> int:
    """Own size once per binary, independent of host, path and workload seed."""
    if profile.logical_size_bytes.min == profile.logical_size_bytes.max:
        return profile.logical_size_bytes.min
    with generation_seed_scope(DEFAULT_GENERATION_SEED):
        rng = random.Random(_stable_seed(f"macos-installed-size:{binary.content_id}"))
    distribution = NormalDist(math.log(profile.size_median_bytes), profile.size_log_sigma)
    lower = distribution.cdf(math.log(profile.logical_size_bytes.min))
    upper = distribution.cdf(math.log(profile.logical_size_bytes.max))
    # Open-interval sampling keeps inverse-CDF endpoints finite without retries.
    fraction = (rng.getrandbits(52) + 0.5) / 2**52
    quantile = lower + (upper - lower) * fraction
    quantile = min(math.nextafter(1.0, 0.0), max(math.nextafter(0.0, 1.0), quantile))
    result = int(math.exp(distribution.inv_cdf(quantile)))
    return min(profile.logical_size_bytes.max, max(profile.logical_size_bytes.min, result))


def _file_spec(
    installation: SoftwareInstallationIdentity,
    binary: BinaryReleaseIdentity,
    path: str,
    *,
    profile: MacosInstalledFileProfile,
    window_start: datetime,
    window_end: datetime,
    uid: int,
    gid: int,
    size: int,
    available_from: date | None,
) -> MacosInstalledFileSpec:
    # Copy/install times belong to placement; a release's content date is shared
    # across the fleet, independent of installation ordering or local filenames.
    rng = random.Random(
        _stable_seed(f"macos-installed-placement:{installation.installation_id}:{path}")
    )
    with generation_seed_scope(DEFAULT_GENERATION_SEED):
        build_rng = random.Random(_stable_seed(f"macos-installed-build:{binary.content_id}"))
    age = rng.randint(profile.installation_age_seconds.min, profile.installation_age_seconds.max)
    born = _time(window_start - timedelta(seconds=age), rng)
    modified = _time(
        window_start
        - timedelta(
            seconds=profile.installation_age_seconds.max
            + build_rng.randint(profile.build_lead_seconds.min, profile.build_lead_seconds.max)
        ),
        build_rng,
    )
    accessed = (
        born if age == 1 else _time(window_start - timedelta(seconds=rng.randint(1, age - 1)), rng)
    )
    valid_from = window_start
    if available_from is not None:
        boundary = datetime(
            available_from.year, available_from.month, available_from.day, tzinfo=UTC
        )
        valid_from = max(window_start, boundary)
        if valid_from >= window_end:
            raise StateError(
                "Mac installed provisioning requires a release available in its window"
            )
        delta = boundary - datetime(1970, 1, 1, tzinfo=UTC)
        floor = MacosFileTime(seconds=delta.days * 86400, nanoseconds=0)

        def time_key(value: MacosFileTime) -> tuple[int, int]:
            return value.seconds, value.nanoseconds

        born = max(born, floor, key=time_key)
        modified = max(modified, floor, key=time_key)
        accessed = max(accessed, born, key=time_key)
    unit = profile.allocation_unit_bytes
    return MacosInstalledFileSpec(
        installation_id=installation.installation_id,
        native_path=path,
        volume_id=profile.volume_id,
        valid_from=valid_from,
        valid_until=window_end,
        permissions=profile.permissions,
        uid=uid,
        gid=gid,
        accessed=accessed,
        modified=modified,
        changed=born,
        born=born,
        size_bytes=size,
        allocated_blocks=((size + unit - 1) // unit) * (unit // 512),
        flags=profile.flags,
        generation=profile.generation,
    )


def compile_macos_installed_provisioning(
    scenario: Scenario,
    deployments: DeploymentContentRegistry,
    identities: IdentityDirectory,
    *,
    window_start: datetime,
    window_end: datetime,
) -> MacosInstalledProvisioning | None:
    """Produce one frozen native-stat owner for explicitly modeled arm64 Mac hosts.

    Empty non-Mac fleets do not load this profile. Machine files use the host's
    resolved root account; user files require that principal's exact local
    account. Unknown ownership stays unavailable rather than borrowing root or
    another host. A later native source must require a complete observation.
    """
    if (
        type(scenario) is not Scenario
        or type(deployments) is not DeploymentContentRegistry
        or type(identities) is not IdentityDirectory
        or type(window_start) is not datetime
        or type(window_end) is not datetime
        or window_start.utcoffset() is None
        or window_end.utcoffset() is None
        or window_start >= window_end
    ):
        raise StateError(
            "Mac installed provisioning requires exact owners and an aware finite window"
        )
    hosts = sorted(
        system.hostname
        for system in scenario.environment.systems
        if platform_for_os(system.os) == "macos" and system.architecture == "arm64"
    )
    if not hosts:
        return None
    profile = load_macos_installed_file_profile()
    if profile is None:
        return None
    volumes: list[MacosInstalledVolumeSpec] = []
    files: list[MacosInstalledFileSpec] = []
    unavailable: list[MacosUnprovisionedInstallation] = []
    sizes: dict[str, int] = {}
    for host in hosts:
        rng = random.Random(_stable_seed(f"macos-installed-volume:{host.casefold()}"))
        volumes.append(
            MacosInstalledVolumeSpec(
                hostname=host,
                volume_id=profile.volume_id,
                device=rng.randint(profile.volume_device.min, profile.volume_device.max),
                first_inode=rng.randint(profile.first_inode.min, profile.first_inode.max),
                preferred_block_size=profile.allocation_unit_bytes,
            )
        )
        for installation in deployments.iter_installations_on_host(host):
            if installation.platform != "macos":
                continue
            owner = identities.macos_account(
                "root" if installation.scope == "machine" else installation.principal, host
            )
            if owner is None:
                unavailable.append(
                    MacosUnprovisionedInstallation(
                        installation.installation_id, installation.principal, host
                    )
                )
                continue
            for path in installation.image_paths:
                selected = deployments.installation_for_image(
                    host, path, "macos", principal=installation.principal
                )
                if selected is None:
                    raise StateError("Mac installed provisioning lost its exact path binding")
                if selected != installation:
                    # Logical module/SDK entry points can share one native image.
                    # The registry already authenticates its single path/content
                    # binding; only that physical owner receives stat/inode facts.
                    continue
                binary = deployments.resolve_binary(
                    host, path, "macos", principal=installation.principal
                )
                if binary is None or binary.key.architecture != "arm64":
                    raise StateError(
                        "Mac installed provisioning lost its exact arm64 deployed binary"
                    )
                if binary.content_id not in sizes:
                    sizes[binary.content_id] = _release_size(binary, profile)
                files.append(
                    _file_spec(
                        installation,
                        binary,
                        path,
                        profile=profile,
                        window_start=window_start,
                        window_end=window_end,
                        uid=owner.uid,
                        gid=owner.gid,
                        size=sizes[binary.content_id],
                        available_from=deployments.binary_available_from(binary.content_id),
                    )
                )
    return MacosInstalledProvisioning(
        MacosInstalledFilesystem(deployments, volumes=volumes, files=files),
        len(files),
        tuple(sorted(unavailable, key=lambda item: (item.hostname, item.installation_id))),
    )
