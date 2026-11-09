# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Files sender locality follows direction and the actual sensor view."""

from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import FileTransferContext, X509Context
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek_base import native_zeek_file_sender_locality
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from tests.unit.test_network_observation import _network_event, _visibility_engine


@pytest.mark.parametrize("is_orig", [True, False])
@pytest.mark.parametrize("local_orig", [True, False, None])
@pytest.mark.parametrize("local_resp", [True, False, None])
def test_sender_locality_retains_unknown_and_both_endpoint_views(
    is_orig: bool, local_orig: bool | None, local_resp: bool | None
) -> None:
    assert native_zeek_file_sender_locality(is_orig, local_orig, local_resp) is (
        local_orig if is_orig else local_resp
    )


@pytest.mark.parametrize("is_orig", [True, False])
@pytest.mark.parametrize(
    "local_orig,local_resp", [(True, False), (False, True), (True, True), (False, False)]
)
def test_transfer_and_certificate_share_sender_projection(
    tmp_path: Path, is_orig: bool, local_orig: bool, local_resp: bool
) -> None:
    event = _network_event(protocol="tcp")
    event.network = replace(event.network, local_orig=local_orig, local_resp=local_resp)
    event.file_transfer = FileTransferContext(
        fuid="Fsender", source="HTTP", is_orig=is_orig, seen_bytes=100, total_bytes=100
    )
    event.x509 = X509Context(fuid="Fcertificate", fingerprint="a" * 40)
    emitter = ZeekFilesEmitter(load_format("zeek_files"), tmp_path / "files.json", threaded=False)
    emitter.emit_event = Mock()
    emitter.emit(event)
    rows = [call.args[0] for call in emitter.emit_event.call_args_list]
    transfer = next(row for row in rows if row["fuid"] == "Fsender")
    cert = next(row for row in rows if row["fuid"] == "Fcertificate")
    assert transfer["local_orig"] is (local_orig if is_orig else local_resp)
    assert cert["local_orig"] is local_resp
    assert transfer["tx_hosts"] == [event.network.src_ip if is_orig else event.network.dst_ip]
    planner = NetworkObservationPlanner(_visibility_engine())
    observation = planner.plan(
        event, {"zeek_files"}, sensor_formats={"source-tap": {"zeek_files"}}
    )[0]
    # The sensor can have a different locality view from direct canonical rendering.
    observation = replace(observation, local_orig=not local_orig, local_resp=not local_resp)
    for row in rows:
        emitter._apply_sensor_observation(row, observation, event.timestamp)
        assert row["local_orig"] is (
            observation.local_orig if row["is_orig"] else observation.local_resp
        )
        assert row["conn_uids"] == [observation.connection_uid]
    assert event.network.local_orig is local_orig
    assert event.network.local_resp is local_resp
    emitter.close()
