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

"""Adversarial contract tests for durable network-request identity."""

import os
import subprocess
import sys
import threading
import tracemalloc
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from enum import Enum
from typing import NamedTuple
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest
from pydantic import BaseModel, ConfigDict

from evidenceforge.events.content_identity import BinaryReleaseIdentity, BinaryReleaseKey
from evidenceforge.events.contexts import (
    DnsContext,
    EmailContext,
    FileTransferContext,
    FirewallContext,
    HttpContext,
    IdsAlertPlan,
    OcspContext,
    PeContext,
    SslContext,
)
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.actions.network_identity import (
    _NETWORK_CONNECTION_IDENTITY_EXCLUDED_FIELDS,
    _network_request_identity_fields,
    _trusted_network_request_stable_id,
)
from evidenceforge.models import System
from evidenceforge.utils.rng import generation_seed_scope

pytestmark = pytest.mark.slow


class _IdentityString(str):
    """Distinct string semantic type used by stable-ID boundary tests."""


class _IdentityInteger(int):
    """Distinct integer semantic type used by stable-ID boundary tests."""


class _IdentityFloat(float):
    """Distinct float semantic type used by stable-ID boundary tests."""


class _IdentityBytes(bytes):
    """Distinct bytes semantic type used by stable-ID boundary tests."""


class _IdentityBytearray(bytearray):
    """Distinct bytearray semantic type used by stable-ID boundary tests."""


class _IdentityDate(date):
    """Distinct date semantic type used by stable-ID boundary tests."""


class _IdentityDatetime(datetime):
    """Distinct datetime semantic type used by stable-ID boundary tests."""


class _IdentityTimedelta(timedelta):
    """Distinct timedelta semantic type used by stable-ID boundary tests."""


def _request_with_payload(payload: object) -> NetworkConnectionRequest:
    """Return one request carrying an arbitrary public email attachment value."""

    return NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        email=EmailContext(
            message_id="message-1",
            artifact_id="artifact-1",
            envelope_from="sender@example.test",
            header_from="sender@example.test",
            attachments=[{"payload": payload}],
        ),
    )


def _assert_mutable_payload_race_is_bounded(
    payload: object,
    mutate: Callable[[], None],
    allowed_stable_ids: set[str],
    allowed_errors: tuple[str, ...],
    *,
    attempts: int = 300,
) -> None:
    """Exercise one exact mutable payload while another thread alternates its state."""

    stop = threading.Event()
    started = threading.Event()
    completed_cycles = [0]

    def mutate_until_stopped() -> None:
        started.set()
        while not stop.is_set():
            try:
                mutate()
            except BufferError:
                # An internal bytearray view intentionally pins resize while one
                # bounded scalar snapshot is being authenticated.
                continue
            completed_cycles[0] += 1

    original_switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    worker = threading.Thread(target=mutate_until_stopped, daemon=True)
    worker.start()
    assert started.wait(timeout=5)
    try:
        for _ in range(attempts):
            try:
                stable_id = _request_with_payload(payload).stable_id
            except ValueError as exc:
                assert type(exc) is ValueError
                assert any(fragment in str(exc) for fragment in allowed_errors), str(exc)
            else:
                assert stable_id in allowed_stable_ids
    finally:
        stop.set()
        worker.join(timeout=5)
        sys.setswitchinterval(original_switch_interval)

    assert not worker.is_alive()
    assert completed_cycles[0] > 0


def test_network_request_identity_field_census_matches_current_public_model() -> None:
    """Every current semantic field is encoded and only exact carriers are excluded."""

    expected_semantic_fields = (
        "src_ip",
        "dst_ip",
        "time",
        "dst_port",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "src_port",
        "emit_dns",
        "pid",
        "source_system",
        "conn_state",
        "dns",
        "email",
        "smtp",
        "ssl",
        "x509",
        "x509_chain",
        "tls_presentation",
        "ids_alerts",
        "http",
        "file_transfer",
        "file_transfers",
        "pe",
        "pe_analyses",
        "ocsp",
        "ocsp_transaction",
        "proxy",
        "firewall",
        "hostname",
        "proxy_bypass",
        "suppress_direct_http_channel",
        "process_image",
        "preserve_dst_ip",
        "preserve_http_outcome",
        "suppress_application_side_effects",
        "suppress_source_pid_inference",
        "preserve_explicit_payload",
        "suppress_prereq_dns",
        "packet_overhead_bytes",
        "responding_pid",
        "ssh_attempted_username",
        "parent_action_group_id",
        "preserve_start_time",
        "transport_lifecycle_mode",
        "persistent_smb_root_intent",
        "defer_source_publication",
        "source",
    )
    expected_carriers = {
        "deferred_session_authority",
        "identity_capture",
        "persistent_smb_application_intent",
        "persistent_smb_file_mutation_journal",
        "persistent_smb_terminal_authority",
        "persistent_smb_terminal_continuation",
        "prepared_application_token",
        "explicit_proxy_open_preparation",
        "explicit_proxy_request_preparation",
    }
    request = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )
    request_fields = fields(NetworkConnectionRequest)

    assert _NETWORK_CONNECTION_IDENTITY_EXCLUDED_FIELDS == expected_carriers
    assert {
        request_field.name
        for request_field in request_fields
        if not request_field.compare and not request_field.repr
    } == expected_carriers
    assert (
        tuple(request_field.name for request_field in request_fields if request_field.compare)
        == expected_semantic_fields
    )
    assert tuple(
        name for name, _value in _network_request_identity_fields(request, NetworkConnectionRequest)
    ) == (expected_semantic_fields)


def test_network_request_identity_uses_full_width_collision_resistance() -> None:
    """The known colliding real DNS transports receive distinct full-width IDs."""

    first = NetworkConnectionRequest(
        src_ip="10.20.10.10",
        dst_ip="10.20.30.10",
        time=datetime.fromisoformat("2024-11-12T14:50:57.934286+00:00"),
        dst_port=53,
        proto="udp",
        service="dns",
        orig_bytes=81,
        resp_bytes=196,
        src_port=49152,
        dns=DnsContext(query="cdn.onenote.net", query_type="A"),
    )
    second = NetworkConnectionRequest(
        src_ip="10.20.10.15",
        dst_ip="10.20.30.10",
        time=datetime.fromisoformat("2024-11-12T15:37:51.480081+00:00"),
        dst_port=53,
        proto="udp",
        service="dns",
        orig_bytes=53,
        resp_bytes=261,
        src_port=55260,
        dns=DnsContext(query="hpia.hpcloud.hp.com", query_type="A"),
    )

    assert first.stable_id != second.stable_id
    assert UUID(first.stable_id.removeprefix("network-connection-")).version == 4
    assert UUID(second.stable_id.removeprefix("network-connection-")).version == 4


def test_trusted_network_request_identity_matches_public_encoder_bytes() -> None:
    """The planner fast path preserves exact IDs across representative graphs and seeds."""

    requests = (
        NetworkConnectionRequest(
            src_ip="10.0.0.10",
            dst_ip="203.0.113.10",
            time=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
        ),
        NetworkConnectionRequest(
            src_ip="10.0.0.20",
            dst_ip="10.0.0.53",
            time=datetime(2026, 8, 30, 12, 1, tzinfo=UTC),
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(query="updates.example.test", query_type="AAAA"),
            source_system=System(
                hostname="client-01",
                ip="10.0.0.20",
                os="Linux",
                type="workstation",
            ),
        ),
        _request_with_payload(
            {
                "attachment": ["report.txt", 4096],
                "labels": {"department": "finance", "classification": "internal"},
            }
        ),
    )

    ids_by_seed: list[tuple[str, ...]] = []
    for seed in (17, 18):
        with generation_seed_scope(seed):
            public_ids = tuple(request.stable_id for request in requests)
            trusted_ids = tuple(
                _trusted_network_request_stable_id(request, NetworkConnectionRequest)
                for request in requests
            )
        assert trusted_ids == public_ids
        ids_by_seed.append(trusted_ids)

    assert ids_by_seed[0] != ids_by_seed[1]


@pytest.mark.parametrize(
    ("field_name", "present_value"),
    (
        ("duration", 0.0),
        ("orig_bytes", 0),
        ("resp_bytes", 0),
        ("src_port", 0),
        ("packet_overhead_bytes", 0),
        ("service", ""),
    ),
)
def test_network_request_identity_distinguishes_absent_optional_values(
    field_name: str,
    present_value: object,
) -> None:
    """Absent optional values cannot alias explicit zero or empty intent."""

    absent = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )
    present = replace(absent, **{field_name: present_value})

    assert absent.stable_id != present.stable_id


def test_network_request_identity_preserves_scalar_types_and_timestamp_precision() -> None:
    """Equal spellings of distinct scalar types and instants cannot alias."""

    base = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )
    typed_ids = {
        replace(base, orig_bytes=False).stable_id,
        replace(base, orig_bytes=0).stable_id,
        replace(base, orig_bytes=0.0).stable_id,  # type: ignore[arg-type]
        replace(base, orig_bytes="").stable_id,  # type: ignore[arg-type]
    }

    assert len(typed_ids) == 4
    assert base.stable_id != replace(base, time=base.time + timedelta(microseconds=1)).stable_id
    assert replace(base, duration=0.0) == replace(base, duration=-0.0)
    assert replace(base, duration=0.0).stable_id == replace(base, duration=-0.0).stable_id


def test_network_request_identity_canonicalizes_equivalent_timezones() -> None:
    """One instant has one identity across fixed-offset and ZoneInfo spelling."""

    utc_request = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        http=HttpContext(canonical_request_time=datetime(2026, 7, 14, 12, 0, 1, tzinfo=UTC)),
    )
    fixed_offset = replace(
        utc_request,
        time=datetime(2026, 7, 14, 7, 0, tzinfo=timezone(timedelta(hours=-5))),
        http=replace(
            utc_request.http,
            canonical_request_time=datetime(
                2026,
                7,
                14,
                7,
                0,
                1,
                tzinfo=timezone(timedelta(hours=-5)),
            ),
        ),
    )
    zone_info = replace(
        utc_request,
        time=datetime(2026, 7, 14, 8, 0, tzinfo=ZoneInfo("America/New_York")),
        http=replace(
            utc_request.http,
            canonical_request_time=datetime(
                2026,
                7,
                14,
                8,
                0,
                1,
                tzinfo=ZoneInfo("America/New_York"),
            ),
        ),
    )

    assert utc_request.stable_id == fixed_offset.stable_id == zone_info.stable_id


@pytest.mark.parametrize(
    ("field_name", "first_value", "second_value"),
    (
        (
            "dns",
            DnsContext(query="example.test", response_ip="192.0.2.10"),
            DnsContext(query="example.test", response_ip="192.0.2.11"),
        ),
        (
            "email",
            EmailContext("m1", "a1", "sender@example.test", "sender@example.test"),
            EmailContext("m1", "a1", "sender@example.test", "sender@example.test", subject="x"),
        ),
        ("ssl", SslContext(server_name="one.test"), SslContext(server_name="two.test")),
        ("http", HttpContext(status_code=200), HttpContext(status_code=404)),
        (
            "file_transfer",
            FileTransferContext(fuid="F1", filename="one.bin"),
            FileTransferContext(fuid="F1", filename="two.bin"),
        ),
        (
            "ids_alerts",
            (IdsAlertPlan(sid=1, message="first", classification="attempt"),),
            (IdsAlertPlan(sid=1, message="second", classification="attempt"),),
        ),
        ("pe", PeContext(id="F1"), PeContext(id="F2")),
        ("ocsp", OcspContext(id="F1"), OcspContext(id="F2")),
        (
            "firewall",
            FirewallContext("permit", 302013, 1, "inside", "outside"),
            FirewallContext("permit", 302015, 1, "inside", "outside"),
        ),
        ("suppress_direct_http_channel", False, True),
        (
            "source_system",
            System(
                hostname="WS-01",
                ip="10.0.0.10",
                os="Windows 11",
                type="workstation",
                roles=["client"],
            ),
            System(
                hostname="WS-01",
                ip="10.0.0.10",
                os="Ubuntu 24.04",
                type="workstation",
                roles=["client", "developer"],
            ),
        ),
    ),
)
def test_network_request_identity_covers_nested_public_semantics(
    field_name: str,
    first_value: object,
    second_value: object,
) -> None:
    """Nested semantic differences contribute their complete value."""

    base = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )

    assert (
        replace(base, **{field_name: first_value}).stable_id
        != replace(base, **{field_name: second_value}).stable_id
    )


def test_network_request_identity_orders_mappings_and_rejects_invalid_values() -> None:
    """Mappings are order-independent while cycles, unsupported values, and NaN reject."""

    first = _request_with_payload({"first": "1", "second": "2"})
    reordered = _request_with_payload({"second": "2", "first": "1"})
    recursive: dict[str, object] = {}
    recursive["self"] = recursive

    assert first.stable_id == reordered.stable_id
    with pytest.raises(ValueError, match="recursive value"):
        _ = _request_with_payload(recursive).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(object()).stable_id
    with pytest.raises(ValueError, match="must be finite"):
        _ = replace(first, duration=float("nan")).stable_id


def test_network_request_identity_encodes_pydantic_fields_and_ordered_extras() -> None:
    """Every public field and raw public extra of the trusted model contributes."""

    def system(hostname: str, extras: dict[str, object]) -> System:
        value = System(hostname=hostname, ip="10.0.0.10", os="Linux", type="server")
        object.__setattr__(value, "__pydantic_extra__", extras)
        return value

    first = replace(
        _request_with_payload(None),
        source_system=system("same", {"alpha": 1, "beta": 2}),
    )
    reordered = replace(
        _request_with_payload(None),
        source_system=system("same", {"beta": 2, "alpha": 1}),
    )
    changed_field = replace(
        _request_with_payload(None),
        source_system=system("changed", {"alpha": 1, "beta": 2}),
    )
    changed_extra = replace(
        _request_with_payload(None),
        source_system=system("same", {"alpha": 1, "beta": 3}),
    )
    default_extras = replace(
        _request_with_payload(None),
        source_system=System(
            hostname="same",
            ip="10.0.0.10",
            os="Linux",
            type="server",
        ),
    )
    empty_extras = replace(
        _request_with_payload(None),
        source_system=system("same", {}),
    )

    assert first.stable_id == reordered.stable_id
    assert first.stable_id != changed_field.stable_id
    assert first.stable_id != changed_extra.stable_id
    assert default_extras.source_system == empty_extras.source_system
    assert default_extras.stable_id == empty_extras.stable_id


def test_network_request_identity_tags_container_and_scalar_concrete_types() -> None:
    """Exact supported concrete families are framed distinctly; subclasses reject."""

    class FirstPair(NamedTuple):
        left: str
        right: str

    class SecondPair(NamedTuple):
        left: str
        right: str

    class SemanticList(list[str]):
        pass

    supported_values = (
        ("a", "b"),
        ["a", "b"],
        "same",
        7,
        1.5,
        b"same",
        bytearray(b"same"),
        date(2026, 7, 14),
        datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        timedelta(seconds=3),
    )
    unsupported_values = (
        FirstPair("a", "b"),
        SecondPair("a", "b"),
        SemanticList(("a", "b")),
        _IdentityString("same"),
        _IdentityInteger(7),
        _IdentityFloat(1.5),
        _IdentityBytes(b"same"),
        _IdentityBytearray(b"same"),
        _IdentityDate(2026, 7, 14),
        _IdentityDatetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        _IdentityTimedelta(seconds=3),
    )

    assert len({_request_with_payload(value).stable_id for value in supported_values}) == len(
        supported_values
    )
    for value in unsupported_values:
        with pytest.raises(TypeError, match="unsupported semantic type"):
            _ = _request_with_payload(value).stable_id


def test_network_request_identity_rejects_hostile_builtin_subclasses_without_callbacks() -> None:
    """Scalar/list/tuple subclasses reject before any caller storage callback."""

    callbacks: list[str] = []

    def callback(name: str) -> None:
        callbacks.append(name)
        raise AssertionError(f"caller callback executed: {name}")

    class HostileString(str):
        def __getattribute__(self, name: str) -> object:
            callback(f"str.getattribute:{name}")

        def __str__(self) -> str:
            callback("str.str")

    class HostileBytes(bytes):
        def __getattribute__(self, name: str) -> object:
            callback(f"bytes.getattribute:{name}")

        def __bytes__(self) -> bytes:
            callback("bytes.bytes")

        def hex(self) -> str:
            callback("bytes.hex")

    class HostileList(list[str]):
        def __getattribute__(self, name: str) -> object:
            callback(f"list.getattribute:{name}")

        def __iter__(self):  # type: ignore[no-untyped-def]
            callback("list.iter")

        def __getitem__(self, key: object) -> object:
            callback("list.getitem")

        def copy(self) -> list[str]:
            callback("list.copy")

    class HostileTuple(tuple[str, ...]):
        def __getattribute__(self, name: str) -> object:
            callback(f"tuple.getattribute:{name}")

        def __iter__(self):  # type: ignore[no-untyped-def]
            callback("tuple.iter")

        def __getitem__(self, key: object) -> object:
            callback("tuple.getitem")

    class HostileDate(date):
        def __getattribute__(self, name: str) -> object:
            callback(f"date.getattribute:{name}")

        def isoformat(self) -> str:
            callback("date.isoformat")

    class HostileDatetime(datetime):
        def __getattribute__(self, name: str) -> object:
            callback(f"datetime.getattribute:{name}")

        def astimezone(self, tz: tzinfo | None = None) -> datetime:
            callback("datetime.astimezone")

        def isoformat(self, *args: object, **kwargs: object) -> str:
            callback("datetime.isoformat")

    class HostileTimedelta(timedelta):
        def __getattribute__(self, name: str) -> object:
            callback(f"timedelta.getattribute:{name}")

        @property
        def days(self) -> int:
            callback("timedelta.days")

        @property
        def seconds(self) -> int:
            callback("timedelta.seconds")

        @property
        def microseconds(self) -> int:
            callback("timedelta.microseconds")

    values = (
        HostileString("same"),
        HostileBytes(b"same"),
        HostileList(("a", "b")),
        HostileTuple(("a", "b")),
        HostileDate(2026, 7, 14),
        HostileDatetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        HostileTimedelta(seconds=3),
    )

    for value in values:
        with pytest.raises(TypeError, match="unsupported semantic type"):
            _ = _request_with_payload(value).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_hostile_mapping_set_and_enum_without_callbacks() -> None:
    """Mapping, set, and Enum subclasses reject before caller iteration or access."""

    callbacks: list[str] = []

    def callback(name: str) -> None:
        callbacks.append(name)
        raise AssertionError(f"caller callback executed: {name}")

    class HostileDict(dict[str, str]):
        def __getattribute__(self, name: str) -> object:
            callback(f"dict.getattribute:{name}")

        def __iter__(self):  # type: ignore[no-untyped-def]
            callback("dict.iter")

        def items(self):  # type: ignore[no-untyped-def]
            callback("dict.items")

        def copy(self) -> dict[str, str]:
            callback("dict.copy")

    class HostileSet(set[str]):
        def __getattribute__(self, name: str) -> object:
            callback(f"set.getattribute:{name}")

        def __iter__(self):  # type: ignore[no-untyped-def]
            callback("set.iter")

        def copy(self) -> set[str]:
            callback("set.copy")

    armed = False

    class HostileEnum(Enum):
        VALUE = "same"

        def __getattribute__(self, name: str) -> object:
            if armed:
                callback(f"enum.getattribute:{name}")
            return Enum.__getattribute__(self, name)

    armed = True
    values = (
        HostileDict({"a": "1", "b": "2"}),
        HostileSet({"a", "b"}),
        HostileEnum.VALUE,
    )

    for value in values:
        with pytest.raises(TypeError, match="unsupported semantic type"):
            _ = _request_with_payload(value).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_hostile_metaclass_without_callbacks() -> None:
    """Unsafe metaclasses reject before their type metadata descriptors execute."""

    callbacks: list[str] = []

    class HostileMetaclass(type):
        @property
        def __module__(cls) -> str:
            callbacks.append("module")
            raise AssertionError("caller metaclass descriptor executed")

        def __getattribute__(cls, name: str) -> object:
            callbacks.append(name)
            raise AssertionError("caller metaclass access executed")

    class HostileType(metaclass=HostileMetaclass):
        pass

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(object.__new__(HostileType)).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_metaclass_hash_before_type_cache_lookup() -> None:
    """Type caches authenticate a metaclass before hashing its class object."""

    callbacks: list[str] = []
    armed = False

    class HashingMetaclass(type):
        def __hash__(cls) -> int:
            if armed:
                callbacks.append("hash")
                raise RuntimeError("caller callback executed")
            return type.__hash__(cls)

    class HostileType(metaclass=HashingMetaclass):
        pass

    value = object.__new__(HostileType)
    armed = True

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(value).stable_id
    assert callbacks == []


def test_network_request_identity_does_not_hash_trusted_pydantic_class() -> None:
    """Identity-indexed caches do not dispatch a mutable trusted metaclass hash."""

    callbacks: list[str] = []
    system = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    model_metaclass = type(System)
    metaclass_namespace = type.__getattribute__(model_metaclass, "__dict__")
    original_hash = metaclass_namespace.get("__hash__")

    def hostile_hash(cls: type[object]) -> int:
        callbacks.append("hash")
        raise RuntimeError("caller callback executed")

    type.__setattr__(model_metaclass, "__hash__", hostile_hash)
    try:
        _ = replace(_request_with_payload(None), source_system=system).stable_id
    finally:
        if original_hash is None:
            type.__delattr__(model_metaclass, "__hash__")
        else:
            type.__setattr__(model_metaclass, "__hash__", original_hash)
    assert callbacks == []


def test_network_request_identity_rejects_hostile_class_namespace_key_without_callbacks() -> None:
    """Raw class metadata keys are authenticated before mapping-proxy lookup."""

    callbacks: list[str] = []
    armed = False

    class HostileKey(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            if armed:
                callbacks.append("eq")
                raise RuntimeError("caller callback executed")
            return str.__eq__(self, other)

    hostile_type = type(
        "HostileNamespace",
        (),
        {HostileKey("__dataclass_fields__"): None},
    )
    armed = True

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(object.__new__(hostile_type)).stable_id
    assert callbacks == []


def test_network_request_identity_cycle_and_invalid_extra_controls() -> None:
    """Exact-list cycles and invalid trusted-model extras cannot escape validation."""

    cycle: list[object] = []
    cycle.append(cycle)
    invalid_object = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    invalid_float = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    object.__setattr__(invalid_object, "__pydantic_extra__", {"public_extra": object()})
    object.__setattr__(invalid_float, "__pydantic_extra__", {"public_extra": float("nan")})

    with pytest.raises(ValueError, match="recursive value"):
        _ = _request_with_payload(cycle).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = replace(_request_with_payload(None), source_system=invalid_object).stable_id
    with pytest.raises(ValueError, match="must be finite"):
        _ = replace(_request_with_payload(None), source_system=invalid_float).stable_id


def test_network_request_identity_unsupported_values_do_not_dispatch_class_or_repr() -> None:
    """Unsupported objects fail by exact type without class or repr hooks."""

    callbacks: list[str] = []

    class HostileUnsupported:
        @property
        def __class__(self) -> type[object]:
            callbacks.append("class")
            raise AssertionError("caller class property executed")

        def __repr__(self) -> str:
            callbacks.append("repr")
            raise AssertionError("caller repr executed")

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(HostileUnsupported()).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_nominal_type_spoofing() -> None:
    """Caller types cannot impersonate builtins or replace one nominal binding over time."""

    fake_string = type(
        "str",
        (str,),
        {"__module__": "builtins", "__qualname__": "str"},
    )
    first_peer = type("SameNominalType", (str,), {"__module__": __name__})
    second_peer = type("SameNominalType", (str,), {"__module__": __name__})

    exact_id = _request_with_payload("same").stable_id
    assert exact_id == _request_with_payload("same").stable_id
    for value in (fake_string("same"), first_peer("same"), second_peer("same")):
        with pytest.raises(TypeError, match="unsupported semantic type"):
            _ = _request_with_payload(value).stable_id


def test_network_request_identity_stable_id_emits_no_sensitive_audit_events() -> None:
    """Stable encoding performs no runtime compile or function-sensitive introspection."""

    script = """
import sys
from datetime import UTC, datetime
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest

request = NetworkConnectionRequest(
    src_ip="10.0.0.10",
    dst_ip="203.0.113.10",
    time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
)

def reject_sensitive_event(event, args):
    if event in {"compile", "exec", "object.__getattr__"}:
        raise RuntimeError(f"caller audit callback executed: {event}")

sys.addaudithook(reject_sensitive_event)
print(request.stable_id)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert result.stdout.startswith("network-connection-")


def test_network_request_identity_rejects_hostile_dataclass_and_model_storage() -> None:
    """External dataclass/model fields reject before properties or attribute overrides."""

    callbacks: list[str] = []

    @dataclass(slots=True)
    class HostileDataclass:
        value: str

        def __getattribute__(self, name: str) -> object:
            callbacks.append(f"dataclass:{name}")
            raise AssertionError("caller dataclass access executed")

    class HostileModel(BaseModel):
        model_config = ConfigDict(extra="allow")

        declared: str

        def __getattribute__(self, name: str) -> object:
            if name in {"declared", "public_extra", "__dict__", "__pydantic_extra__"}:
                callbacks.append(f"model:{name}")
                raise AssertionError("caller Pydantic access executed")
            return BaseModel.__getattribute__(self, name)

    model = HostileModel(declared="same", public_extra=_IdentityString("one"))
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(HostileDataclass("same")).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(model).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_pydantic_private_state() -> None:
    """Private equality state on the trusted model rejects instead of colliding."""

    first = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    second = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    default_private = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    empty_private = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    object.__setattr__(first, "__pydantic_private__", {"semantic": "left"})
    object.__setattr__(second, "__pydantic_private__", {"semantic": "right"})
    object.__setattr__(empty_private, "__pydantic_private__", {})

    assert first != second
    _ = replace(_request_with_payload(None), source_system=default_private).stable_id
    with pytest.raises(TypeError, match="cannot encode Pydantic private attributes"):
        _ = replace(_request_with_payload(None), source_system=empty_private).stable_id
    with pytest.raises(TypeError, match="cannot encode Pydantic private attributes"):
        _ = replace(_request_with_payload(None), source_system=first).stable_id
    with pytest.raises(TypeError, match="cannot encode Pydantic private attributes"):
        _ = replace(_request_with_payload(None), source_system=second).stable_id


def test_network_request_identity_rejects_pydantic_instance_shadow_state() -> None:
    """Undeclared raw model keys cannot affect equality while escaping identity."""

    first = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    second = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    object.__setattr__(
        first,
        "__pydantic_generic_metadata__",
        {"origin": str, "args": (), "parameters": ()},
    )
    object.__setattr__(
        second,
        "__pydantic_generic_metadata__",
        {"origin": int, "args": (), "parameters": ()},
    )

    assert first != second
    with pytest.raises(TypeError, match="Pydantic field storage contains undeclared state"):
        _ = replace(_request_with_payload(None), source_system=first).stable_id
    with pytest.raises(TypeError, match="Pydantic field storage contains undeclared state"):
        _ = replace(_request_with_payload(None), source_system=second).stable_id


def test_network_request_identity_rejects_custom_pydantic_equality() -> None:
    """A model equality override cannot add semantics outside fields and extras."""

    class CustomEqualityModel(BaseModel):
        visible: str

        def __eq__(self, other: object) -> bool:
            return False

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(CustomEqualityModel(visible="same")).stable_id


def test_network_request_identity_recursively_ignores_dataclass_compare_false_fields() -> None:
    """Nested trusted dataclass identity follows equality and ignores compare-false state."""

    key = BinaryReleaseKey(
        product_id="example",
        version="1",
        build="1",
        architecture="x64",
        platform="windows",
        artifact_name="example.exe",
        variant="release",
    )
    first = BinaryReleaseIdentity(key)
    second = BinaryReleaseIdentity(key)
    object.__setattr__(second, "identity_kind", "caller-cache")
    changed = BinaryReleaseIdentity(replace(key, version="2"))

    assert first == second
    assert _request_with_payload(first).stable_id == _request_with_payload(second).stable_id
    assert _request_with_payload(first).stable_id != _request_with_payload(changed).stable_id


def test_network_request_identity_rejects_non_bool_dataclass_compare_without_callbacks() -> None:
    """Caller truthiness cannot execute if trusted dataclass metadata is mutated."""

    callbacks: list[str] = []

    class Signal:
        def __bool__(self) -> bool:
            callbacks.append("compare")
            raise RuntimeError("caller callback executed")

    identity_kind_field = fields(BinaryReleaseIdentity)[-1]
    original_compare = identity_kind_field.compare
    identity_kind_field.compare = Signal()  # type: ignore[assignment]
    try:
        key = BinaryReleaseKey(
            product_id="example",
            version="1",
            build="1",
            architecture="x64",
            platform="windows",
            artifact_name="example.exe",
            variant="release",
        )
        with pytest.raises(TypeError, match="dataclass compare flag must be an exact bool"):
            _ = _request_with_payload(BinaryReleaseIdentity(key)).stable_id
    finally:
        identity_kind_field.compare = original_compare
    assert callbacks == []


def test_network_request_identity_authenticates_dataclass_default_type_before_hashing() -> None:
    """Descriptor classification cannot hash a hostile class from a field default."""

    callbacks: list[str] = []
    armed = False

    class HashingMetaclass(type):
        def __hash__(cls) -> int:
            if armed:
                callbacks.append("hash")
                raise RuntimeError("caller callback executed")
            return type.__hash__(cls)

    class HostileDefault(metaclass=HashingMetaclass):
        pass

    default_value = object.__new__(HostileDefault)

    @dataclass
    class Defaulted:
        semantic: object = default_value

    value = Defaulted()
    armed = True

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(value).stable_id
    assert callbacks == []


def test_network_request_identity_prioritizes_dataclass_semantics_over_list_storage() -> None:
    """Ambiguous dataclass and builtin storage semantics reject instead of colliding."""

    @dataclass
    class TaggedList(list[object]):
        semantic: str

    first = TaggedList("first")
    second = TaggedList("second")

    assert not first == second
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(first).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(second).stable_id


def test_network_request_identity_rejects_dataclass_without_generated_equality() -> None:
    """Compare flags cannot stand in for a disabled dataclass equality policy."""

    @dataclass(eq=False)
    class EqualityDisabled:
        semantic: str

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(EqualityDisabled("same")).stable_id


def test_network_request_identity_rejects_custom_dataclass_equality() -> None:
    """An explicit equality method cannot smuggle compare-false semantic state."""

    @dataclass
    class CustomEquality:
        visible: str
        semantic: str = field(compare=False)

        def __eq__(self, other: object) -> bool:
            return isinstance(other, CustomEquality) and self.semantic == other.semantic

    first = CustomEquality("same", "left")
    second = CustomEquality("same", "right")

    assert first != second
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(first).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(second).stable_id


def test_network_request_identity_rejects_callback_capable_dataclass_descriptor() -> None:
    """A field stored behind an arbitrary descriptor rejects without reading it."""

    callbacks: list[str] = []
    armed = False

    class Descriptor(str):
        def __get__(self, instance: object, owner: type[object]) -> object:
            if armed:
                callbacks.append("get")
                raise RuntimeError("caller callback executed")
            instance_values = object.__getattribute__(instance, "__dict__")
            return dict.__getitem__(instance_values, "_semantic")

        def __set__(self, instance: object, value: object) -> None:
            if armed:
                callbacks.append("set")
                raise RuntimeError("caller callback executed")
            instance_values = object.__getattribute__(instance, "__dict__")
            dict.__setitem__(instance_values, "semantic", "decoy")
            dict.__setitem__(instance_values, "_semantic", value)

    @dataclass
    class DescriptorBacked:
        semantic: str = Descriptor("default")

    first = DescriptorBacked("left")
    second = DescriptorBacked("right")
    assert first != second
    callbacks.clear()
    armed = True

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(first).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(second).stable_id
    assert callbacks == []


def test_network_request_identity_rejects_unmodeled_builtin_subclass_state() -> None:
    """Builtin subclasses cannot silently discard instance state or custom equality."""

    class StatefulList(list[str]):
        pass

    class CustomEqualityList(list[str]):
        def __eq__(self, other: object) -> bool:
            return False

    stateful = StatefulList(("same",))
    stateful.semantic = "public"

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(stateful).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(CustomEqualityList(("same",))).stable_id


def test_network_request_identity_rejects_external_descriptor_subclass_state() -> None:
    """Read-only descriptor state in a post-builtin MRO mixin cannot be omitted."""

    callbacks: list[str] = []
    external_values: dict[int, str] = {}
    armed = False

    class ExternalDescriptor:
        def __get__(self, instance: object, owner: type[object]) -> str:
            if armed:
                callbacks.append("get")
                raise RuntimeError("caller callback executed")
            return dict.__getitem__(external_values, id(instance))

    class SemanticMixin:
        __slots__ = ()

        semantic = ExternalDescriptor()

    class DescriptorString(str, SemanticMixin):
        __slots__ = ()

    value = DescriptorString("same")
    dict.__setitem__(external_values, id(value), "left")
    armed = True

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(value).stable_id
    assert callbacks == []


def test_network_request_identity_authenticates_enum_member_map() -> None:
    """Enum member storage cannot enter identity through a nominal class label."""

    class MutableMetadata(Enum):
        FIRST = 1
        SECOND = 2

    second_values = object.__getattribute__(MutableMetadata.SECOND, "__dict__")
    dict.__setitem__(second_values, "_name_", "FIRST")
    dict.__setitem__(second_values, "_value_", 1)

    assert MutableMetadata.FIRST is not MutableMetadata.SECOND
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(MutableMetadata.FIRST).stable_id
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(MutableMetadata.SECOND).stable_id


def test_network_request_identity_rejects_custom_enum_equality() -> None:
    """Enum equality overrides cannot add unencoded member semantics."""

    class CustomEqualityEnum(Enum):
        VALUE = 1

        def __eq__(self, other: object) -> bool:
            return False

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(CustomEqualityEnum.VALUE).stable_id


def test_network_request_identity_retains_memoized_scalar_objects() -> None:
    """Ephemeral external descriptors reject before recycled object IDs can matter."""

    @dataclass(init=False)
    class DescriptorScalars(complex):
        first: float
        second: float
        third: float

    DescriptorScalars.first = complex.real  # type: ignore[assignment]
    DescriptorScalars.second = complex.imag  # type: ignore[assignment]
    DescriptorScalars.third = complex.real  # type: ignore[assignment]
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(DescriptorScalars(1, 2)).stable_id
    DescriptorScalars.third = complex.imag  # type: ignore[assignment]
    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(DescriptorScalars(1, 2)).stable_id


def test_network_request_identity_bounds_distinct_type_metadata_work() -> None:
    """The first caller-defined wide type rejects without scanning its metadata."""

    values: list[str] = []
    for type_index in range(300):
        namespace: dict[str, object] = {"__module__": __name__}
        for attribute_index in range(64):
            dict.__setitem__(namespace, f"metadata_{attribute_index}", attribute_index)
        value_type = type(f"WideIdentityString{type_index}", (str,), namespace)
        values.append(value_type("same"))

    with pytest.raises(TypeError, match="unsupported semantic type"):
        _ = _request_with_payload(values).stable_id


def test_network_request_identity_distinguishes_naive_and_aware_datetimes() -> None:
    """Naive wall-clock intent cannot alias an aware UTC instant."""

    naive = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0),
    )
    aware = replace(naive, time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC))

    assert naive != aware
    assert naive.stable_id != aware.stable_id


@pytest.mark.parametrize(
    "value",
    (
        datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14))),
        datetime(9999, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=-12))),
    ),
)
def test_network_request_identity_rejects_datetime_offset_overflow_as_value_error(
    value: datetime,
) -> None:
    """Timezone normalization cannot leak a raw arithmetic OverflowError."""

    with pytest.raises(ValueError, match="outside the supported datetime range") as exc_info:
        _ = _request_with_payload(value).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_rejects_non_utf8_surrogate_text() -> None:
    """Canonical text accepts Unicode scalar values and rejects lone surrogates."""

    with pytest.raises(ValueError, match="valid UTF-8") as exc_info:
        _ = _request_with_payload("\ud800").stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_enforces_exact_depth_boundary() -> None:
    """Root depth zero permits depth 64 and rejects depth 65 deterministically."""

    def nested_payload(list_depth: int) -> object:
        value: object = "leaf"
        for _ in range(list_depth):
            value = [value]
        return value

    _ = _request_with_payload(nested_payload(60)).stable_id
    with pytest.raises(ValueError, match="maximum depth of 64") as exc_info:
        _ = _request_with_payload(nested_payload(61)).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_enforces_exact_container_member_boundary() -> None:
    """One container accepts 4,096 members and rejects 4,097 before copying it."""

    _ = _request_with_payload([None] * 4_096).stable_id
    with pytest.raises(ValueError, match="maximum of 4096 members") as exc_info:
        _ = _request_with_payload([None] * 4_097).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_enforces_total_node_budget() -> None:
    """Exactly 16,384 public traversals pass and the next occurrence rejects."""

    def payload_occurrences(member_count: int) -> list[list[object]]:
        chunks: list[list[object]] = []
        while member_count:
            chunk_size = min(member_count, 4_096)
            chunks.append([None] * chunk_size)
            member_count -= chunk_size
        return chunks

    # The exact-1e8 request/email envelope consumes 79 occurrences, leaving
    # 16,305 public payload members under the 16,384-node contract.
    _ = _request_with_payload(payload_occurrences(16_305)).stable_id
    with pytest.raises(ValueError, match="maximum of 16384 traversed nodes") as exc_info:
        _ = _request_with_payload(payload_occurrences(16_306)).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_enforces_scalar_byte_budget() -> None:
    """A scalar accepts 256 KiB of UTF-8 and rejects the next byte before encoding growth."""

    _ = _request_with_payload("x" * 262_144).stable_id
    with pytest.raises(ValueError, match="maximum scalar size of 262144 bytes") as exc_info:
        _ = _request_with_payload("x" * 262_145).stable_id
    assert type(exc_info.value) is ValueError


@pytest.mark.parametrize(
    "value",
    (
        pytest.param(b"x" * 262_145, id="bytes"),
        pytest.param(bytearray(b"x" * 262_145), id="bytearray"),
        pytest.param(-(1 << (262_144 * 8)), id="negative-int"),
    ),
)
def test_network_request_identity_preflights_binary_and_integer_scalar_sizes(
    value: object,
) -> None:
    """Oversized binary and negative-integer storage rejects before a full copy."""

    with pytest.raises(ValueError, match="maximum scalar size of 262144 bytes") as exc_info:
        _ = _request_with_payload(value).stable_id
    assert type(exc_info.value) is ValueError


@pytest.mark.parametrize("container_kind", ("list", "dict", "set"))
def test_network_request_identity_bounds_concurrent_container_resize(
    container_kind: str,
) -> None:
    """Alternating empty/50k containers never create an oversized identity snapshot."""

    if container_kind == "list":
        payload: object = []
        large: object = [None] * 50_000

        def mutate() -> None:
            list.clear(payload)  # type: ignore[arg-type]
            list.extend(payload, large)  # type: ignore[arg-type]

    elif container_kind == "dict":
        payload = {}
        large = dict.fromkeys(range(50_000))

        def mutate() -> None:
            dict.clear(payload)  # type: ignore[arg-type]
            dict.update(payload, large)  # type: ignore[arg-type]

    else:
        payload = set()
        large = set(range(50_000))

        def mutate() -> None:
            set.clear(payload)  # type: ignore[arg-type]
            set.update(payload, large)  # type: ignore[arg-type]

    empty_stable_id = _request_with_payload(type(payload)()).stable_id
    _assert_mutable_payload_race_is_bounded(
        payload,
        mutate,
        {empty_stable_id},
        (
            "maximum of 4096 members",
            f"{container_kind} changed during identity encoding",
        ),
    )

    with pytest.raises(ValueError, match="maximum of 4096 members") as exc_info:
        _ = _request_with_payload(large).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_bounds_concurrent_bytearray_resize() -> None:
    """An empty preflight can never precede an oversized mutable binary copy."""

    payload = bytearray()
    large = b"x" * 300_000

    def mutate() -> None:
        bytearray.clear(payload)
        bytearray.extend(payload, large)

    empty_stable_id = _request_with_payload(bytearray()).stable_id
    _assert_mutable_payload_race_is_bounded(
        payload,
        mutate,
        {empty_stable_id},
        ("maximum scalar size of 262144 bytes", "bytearray changed during identity encoding"),
    )

    with pytest.raises(ValueError, match="maximum scalar size of 262144 bytes") as exc_info:
        _ = _request_with_payload(bytearray(large)).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_authenticates_concurrent_memoryview_writes() -> None:
    """Same-length writes can only yield a coherent supported bytearray snapshot."""

    first = b"a" * 65_536
    second = b"b" * 65_536
    payload = bytearray(first)
    writer_view = memoryview(payload)

    def mutate() -> None:
        memoryview.__setitem__(writer_view, slice(None), first)
        memoryview.__setitem__(writer_view, slice(None), second)

    allowed_stable_ids = {
        _request_with_payload(bytearray(first)).stable_id,
        _request_with_payload(bytearray(second)).stable_id,
    }
    try:
        _assert_mutable_payload_race_is_bounded(
            payload,
            mutate,
            allowed_stable_ids,
            ("bytearray changed during identity encoding",),
        )
    finally:
        memoryview.release(writer_view)

    unsupported_view = memoryview(payload)
    try:
        with pytest.raises(TypeError, match="unsupported semantic type"):
            _ = _request_with_payload(unsupported_view).stable_id
    finally:
        memoryview.release(unsupported_view)


@pytest.mark.parametrize("container_kind", ("list", "dict", "set"))
def test_network_request_identity_authenticates_same_size_container_aba(
    container_kind: str,
) -> None:
    """Same-cardinality A/B/A mutation yields an operation-reachable bounded state."""

    member_count = 32
    reachable_states: list[object] = []

    if container_kind == "list":
        first: object = ["a"] * member_count
        payload: object = list(first)
        for split in range(member_count + 1):
            reachable_states.append(["b"] * split + ["a"] * (member_count - split))
            reachable_states.append(["a"] * split + ["b"] * (member_count - split))

        def mutate() -> None:
            for index in range(member_count):
                list.__setitem__(payload, index, "b")  # type: ignore[arg-type]
            for index in range(member_count):
                list.__setitem__(payload, index, "a")  # type: ignore[arg-type]

    elif container_kind == "dict":
        first = dict.fromkeys(range(member_count), "a")
        payload = dict(first)
        for split in range(member_count + 1):
            reachable_states.append(
                {index: "b" if index < split else "a" for index in range(member_count)}
            )
            reachable_states.append(
                {index: "a" if index < split else "b" for index in range(member_count)}
            )

        def mutate() -> None:
            for index in range(member_count):
                dict.__setitem__(payload, index, "b")  # type: ignore[arg-type]
            for index in range(member_count):
                dict.__setitem__(payload, index, "a")  # type: ignore[arg-type]

    else:
        first = set(range(member_count))
        payload = set(first)
        toggle_pairs = tuple({index, index + member_count} for index in range(member_count))
        for split in range(member_count + 1):
            reachable_states.append(
                set(range(split, member_count)) | set(range(member_count, member_count + split))
            )
            reachable_states.append(
                set(range(split)) | set(range(member_count + split, member_count * 2))
            )

        def mutate() -> None:
            for pair in toggle_pairs:
                set.symmetric_difference_update(payload, pair)  # type: ignore[arg-type]
            for pair in toggle_pairs:
                set.symmetric_difference_update(payload, pair)  # type: ignore[arg-type]

    allowed_stable_ids = {_request_with_payload(state).stable_id for state in reachable_states}
    _assert_mutable_payload_race_is_bounded(
        payload,
        mutate,
        allowed_stable_ids,
        (f"{container_kind} changed during identity encoding",),
        attempts=200,
    )


def test_network_request_identity_bounds_concurrent_pydantic_storage_mutation() -> None:
    """Trusted model backing storage cannot grow past the snapshot cap mid-read."""

    system = System(hostname="same", ip="10.0.0.1", os="Linux", type="server")
    storage = object.__getattribute__(system, "__dict__")
    assert type(storage) is dict
    baseline_storage = dict.copy(storage)
    oversized_storage = dict.copy(baseline_storage)
    for index in range(5_000):
        dict.__setitem__(oversized_storage, f"shadow_{index}", None)
    request = replace(_request_with_payload(None), source_system=system)
    baseline_stable_id = request.stable_id
    stop = threading.Event()
    started = threading.Event()
    completed_cycles = [0]

    def mutate_until_stopped() -> None:
        started.set()
        while not stop.is_set():
            dict.clear(storage)
            dict.update(storage, oversized_storage)
            dict.clear(storage)
            dict.update(storage, baseline_storage)
            completed_cycles[0] += 1

    original_switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    worker = threading.Thread(target=mutate_until_stopped, daemon=True)
    worker.start()
    assert started.wait(timeout=5)
    try:
        for _ in range(200):
            try:
                stable_id = request.stable_id
            except (TypeError, ValueError) as exc:
                assert type(exc) is TypeError or type(exc) is ValueError
                assert any(
                    fragment in str(exc)
                    for fragment in (
                        "maximum of 4096 members",
                        "dict changed during identity encoding",
                        "Pydantic field storage contains undeclared state",
                        "Pydantic field has no stored value",
                    )
                ), str(exc)
            else:
                assert stable_id == baseline_stable_id
    finally:
        stop.set()
        worker.join(timeout=5)
        sys.setswitchinterval(original_switch_interval)
        dict.clear(storage)
        dict.update(storage, baseline_storage)

    assert not worker.is_alive()
    assert completed_cycles[0] > 0


@pytest.mark.parametrize(
    ("payload", "maximum_peak", "should_reject"),
    (
        pytest.param([None] * 4_096, 256 * 1024, False, id="list-at-cap"),
        pytest.param([None] * 4_097, 256 * 1024, True, id="list-one-over"),
        pytest.param(bytearray(262_144), 512 * 1024, False, id="bytearray-at-cap"),
        pytest.param(bytearray(262_145), 128 * 1024, True, id="bytearray-one-over"),
    ),
)
def test_network_request_identity_snapshot_peak_allocation_is_bounded(
    payload: object,
    maximum_peak: int,
    should_reject: bool,
) -> None:
    """At-cap and oversized inputs cannot create an oversized temporary snapshot."""

    request = _request_with_payload(payload)
    tracemalloc.start()
    try:
        if should_reject:
            with pytest.raises(ValueError):
                _ = request.stable_id
        else:
            _ = request.stable_id
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < maximum_peak


def test_network_request_identity_enforces_aggregate_byte_budget() -> None:
    """The exact last byte under 1 MiB passes and the next canonical byte rejects."""

    prefix = [character * 262_144 for character in "abc"]
    low = 0
    high = 262_144
    while low < high:
        midpoint = (low + high + 1) // 2
        try:
            _ = _request_with_payload([*prefix, "d" * midpoint]).stable_id
        except ValueError:
            high = midpoint - 1
        else:
            low = midpoint

    assert low < 262_144
    _ = _request_with_payload([*prefix, "d" * low]).stable_id
    with pytest.raises(ValueError, match="maximum encoded size of 1048576 bytes") as exc_info:
        _ = _request_with_payload([*prefix, "d" * (low + 1)]).stable_id
    assert type(exc_info.value) is ValueError


def test_network_request_identity_memoizes_alias_dags_without_changing_semantics() -> None:
    """Shared acyclic subgraphs stay linear and match equal copied subgraphs."""

    shared_leaf: object = ["same"]
    aliased = [shared_leaf, shared_leaf]
    copied = [["same"], ["same"]]
    deep_alias: object = "leaf"
    for _ in range(60):
        deep_alias = [deep_alias, deep_alias]

    assert _request_with_payload(aliased).stable_id == _request_with_payload(copied).stable_id
    _ = _request_with_payload(deep_alias).stable_id


def test_network_request_identity_rejects_callback_capable_timezone_before_access() -> None:
    """Arbitrary tzinfo implementations reject without UTC-offset callbacks."""

    callbacks: list[str] = []

    class HostileTimezone(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta | None:
            callbacks.append("utcoffset")
            raise AssertionError("caller timezone callback executed")

        def dst(self, value: datetime | None) -> timedelta | None:
            callbacks.append("dst")
            raise AssertionError("caller timezone callback executed")

        def tzname(self, value: datetime | None) -> str | None:
            callbacks.append("tzname")
            raise AssertionError("caller timezone callback executed")

    with pytest.raises(TypeError, match="callback-capable timezone"):
        _ = _request_with_payload(datetime(2026, 7, 14, 12, 0, tzinfo=HostileTimezone())).stable_id
    assert callbacks == []


def test_network_request_identity_authenticates_timezone_type_namespace_before_labeling() -> None:
    """Even rejection labels cannot look up metadata through hostile namespace keys."""

    callbacks: list[str] = []
    armed = False

    class HostileKey(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            if armed:
                callbacks.append("eq")
                raise RuntimeError("caller callback executed")
            return str.__eq__(self, other)

    hostile_timezone_type = type(
        "HostileTimezoneNamespace",
        (tzinfo,),
        {HostileKey("__module__"): "tests"},
    )
    hostile_timezone = hostile_timezone_type()
    armed = True

    with pytest.raises(TypeError, match="callback-capable timezone"):
        _ = _request_with_payload(datetime(2026, 7, 14, 12, 0, tzinfo=hostile_timezone)).stable_id
    assert callbacks == []


def test_network_request_identity_copy_and_delimiter_boundaries_are_stable() -> None:
    """Equal copies retain identity while field and sequence boundaries remain injective."""

    request = _request_with_payload(
        {"headers": {"x": "y"}, "parts": ["a", "b"], "unordered": {"c", "d"}}
    )
    copied = deepcopy(request)
    base = replace(request, email=None)
    field_boundary_a = replace(base, ssh_attempted_username="a:b", parent_action_group_id="c")
    field_boundary_b = replace(base, ssh_attempted_username="a", parent_action_group_id="b:c")
    sequence_a = replace(base, file_transfers=(FileTransferContext(fuid="a;fuid=b"),))
    sequence_b = replace(
        base,
        file_transfers=(FileTransferContext(fuid="a"), FileTransferContext(fuid="b")),
    )

    assert request == copied
    assert request.stable_id == copied.stable_id
    assert field_boundary_a.stable_id != field_boundary_b.stable_id
    assert sequence_a.stable_id != sequence_b.stable_id


def test_network_request_identity_respects_generation_seed() -> None:
    """The public generation seed namespaces IDs without perturbing repeatability."""

    request = NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        duration=0.0,
        orig_bytes=0,
        resp_bytes=0,
    )
    with generation_seed_scope(7):
        first = request.stable_id
    with generation_seed_scope(7):
        repeated = request.stable_id
    with generation_seed_scope(8):
        other_seed = request.stable_id

    assert first == repeated
    assert first != other_seed


def test_network_request_identity_ignores_python_hash_seed() -> None:
    """Canonical mapping and set ordering cannot depend on process hash randomization."""

    script = """
from datetime import UTC, datetime
from evidenceforge.events.contexts import EmailContext
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest

request = NetworkConnectionRequest(
    src_ip="10.0.0.10",
    dst_ip="203.0.113.10",
    time=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    email=EmailContext(
        message_id="message-1",
        artifact_id="artifact-1",
        envelope_from="sender@example.test",
        header_from="sender@example.test",
        attachments=[{"unordered": {"alpha", "beta", "gamma"}}],
    ),
)
print(request.stable_id)
"""
    stable_ids = []
    for hash_seed in ("1", "99991"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        stable_ids.append(result.stdout.strip())

    assert stable_ids[0] == stable_ids[1]
