# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Windows SSH clients close through the shared exact endpoint publication path."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_ssh_deferred_production import (
    _START,
    _assert_no_dispatcher_residue,
    _fixture,
)

pytestmark = pytest.mark.slow


@pytest.mark.parametrize("threaded", [False, True])
def test_windows_ssh_client_exact_close_reaches_security_and_sysmon_once(
    tmp_path: Path, threaded: bool
) -> None:
    reset_thread_rng(327)
    security_root = tmp_path / "security"
    sysmon_root = tmp_path / "sysmon"
    security = WindowsEventEmitter(
        load_format("windows_event_security"),
        security_root,
        threaded=threaded,
        source_finalization=True,
    )
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=threaded,
        source_finalization=True,
    )
    fixture = _fixture(tmp_path, threaded=threaded)
    logon_id = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        emit_network_evidence=False,
    )
    image = r"C:\Windows\System32\OpenSSH\ssh.exe"
    pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        logon_id,
        image,
        f"{image} analyst@DB-01",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    fixture.generator.dispatcher.emitters.update(
        {"windows_event_security": security, "windows_event_sysmon": sysmon}
    )
    request = replace(
        fixture.request(),
        time=_START + timedelta(seconds=2),
        source_pid=pid,
        source_process_image=image,
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, fixture.generator).execute()
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    coordinator = SourceFinalizationCoordinator(
        (security, sysmon),
        ExactPublicationAuthority(capacity=1, row_capacity=512, byte_capacity=8 * 1024 * 1024),
    )
    coordinator.finalize()
    security.close()
    sysmon.close()
    coordinator.mark_closed()
    rows, _ = fixture.close_and_read()
    assert sum(row.get("action") == "TERMINATE" and row.get("pid") == pid for row in rows) == 1
    security_xml = "\n".join(p.read_text() for p in security_root.rglob("*.xml"))
    sysmon_xml = "\n".join(p.read_text() for p in sysmon_root.rglob("*.xml"))
    assert security_xml.count("<EventID>4689</EventID>") == 1
    assert sysmon_xml.count("<EventID>5</EventID>") == 1
    assert image in security_xml and image in sysmon_xml
