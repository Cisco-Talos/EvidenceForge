# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""eCAR session and SMB file truth follows the identities the eCAR emitter renders."""

from evidenceforge.events.evidence_projection import native_requirements, source_event_contracts


def _samba_facts(kind: str) -> dict:
    return {
        "dst_host": {"hostname": "FILE-LNX-01", "os_category": "linux"},
        "auth": {
            "username": "maya.ross",
            "logon_id": "0x6c0e5ec",
            "auth_session_ref": "c854b434-5b97-4353-936d-eda34c95cb96",
            "session_kind": "smb",
        },
        "smb": {
            "provider": "samba",
            "server_platform": "linux",
            "session_id": "smb-session-000dabec",
            "phase": "read",
            "operation": "read",
            "server_path": "/srv/samba/Share/plan.pdf",
            "client_path": "/Volumes/Share/plan.pdf",
            "local_path": "",
            "file_id": "file-0f8f9d72a86b53c9",
            "local_file_id": "file-0f8f9d72a86b53c9",
        },
        "file": {"path": "/srv/samba/Share/plan.pdf", "action": "read"},
    }


def test_samba_session_truth_uses_smb_session_reference_not_logon_id() -> None:
    (requirement,) = native_requirements(
        "ecar", "logoff", _samba_facts("logoff"), {}, "destination_endpoint"
    )

    assert requirement.selector["session_id"] == "c854b434-5b97-4353-936d-eda34c95cb96"
    assert "logon_id" not in requirement.selector
    assert "logon_id" not in requirement.required


def test_windows_session_truth_keeps_logon_id() -> None:
    facts = {
        "dst_host": {"hostname": "WS-01", "os_category": "windows"},
        "auth": {"username": "alice", "logon_id": "0x3e7a1"},
    }
    (requirement,) = native_requirements("ecar", "logoff", facts, {}, "destination_endpoint")

    assert requirement.selector["logon_id"] == "0x3e7a1"


def test_smb_file_truth_uses_server_and_client_paths_from_smb_facts() -> None:
    facts = _samba_facts("smb_file_read")
    (server,) = native_requirements("ecar", "smb_file_read", facts, {}, "destination_endpoint")
    (client,) = native_requirements("ecar", "smb_file_read", facts, {}, "source_endpoint")

    assert server.required["file_path"] == "/srv/samba/Share/plan.pdf"
    assert client.required["file_path"] == "/Volumes/Share/plan.pdf"


def test_failed_logon_without_source_does_not_select_placeholder_address() -> None:
    facts = {
        "dst_host": {"hostname": "WS-02", "os_category": "windows"},
        "auth": {"username": "sophia.martinez", "logon_id": "", "source_ip": "-"},
    }
    (requirement,) = native_requirements("ecar", "failed_logon", facts, {}, "destination_endpoint")

    assert "src_ip" not in requirement.selector


def test_ecar_contract_actions_match_rendered_native_actions() -> None:
    actions = source_event_contracts()["ecar"]

    assert actions["create_remote_thread"] == ["THREAD", "REMOTE_CREATE"]
    assert actions["process_access"] == ["PROCESS", "OPEN"]
