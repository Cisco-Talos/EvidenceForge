"""Machine task boundaries cannot materialize user-session units as root."""

from types import SimpleNamespace

import pytest

from evidenceforge.generation.activity.systemd_schedules import (
    load_systemd_schedule_descriptors,
    schedule_applies_to_host,
)
from evidenceforge.generation.engine.baseline import _schedule_applies_to_system


@pytest.mark.parametrize("host_type", ["server", "workstation"])
@pytest.mark.parametrize("service,allowed", [("tracker-miner-fs", False), ("updatedb", True)])
def test_machine_task_scope_matches_deployment_and_baseline(
    host_type: str, service: str, allowed: bool
) -> None:
    descriptor = next(s for s in load_systemd_schedule_descriptors() if s.service == service)
    descriptor = descriptor.model_copy(update={"host_probability": 1.0})
    host = SimpleNamespace(
        hostname="linux-host", type=host_type, os="Ubuntu 22.04", roles=[], services=[]
    )
    assert (
        schedule_applies_to_host(
            descriptor, hostname=host.hostname, os_name=host.os, roles=[host_type], services=[]
        )
        is allowed
    )
    assert _schedule_applies_to_system(descriptor.model_dump(), host, False) is allowed
