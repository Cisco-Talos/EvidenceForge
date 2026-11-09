# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical transport histories retain native directional semantics."""

import random

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import ShortCommandTiming, TransportHistoryEntry
from evidenceforge.generation.activity.generator import _choose_ssl_history_from_roll
from evidenceforge.generation.activity.network_params import merge_network_params
from evidenceforge.generation.activity.network_transport import (
    connection_state_distribution,
    native_connection_history,
)
from evidenceforge.generation.activity.process_helpers import _macos_foreground_lifetime


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_configured_transport_vocabulary_records_once_only_classes_once(protocol: str) -> None:
    for _state, _weight, history in connection_state_distribution(protocol):
        assert native_connection_history(history) == history
        assert all(history.count(marker) <= 1 for marker in "aAdDiIqQ")


def test_history_encoding_retains_direction_order_and_repeatable_loss_markers() -> None:
    assert native_connection_history("ShADaDadTtTfFa") == "ShADadTtTfF"
    assert native_connection_history("DdDdDDdd") == "Dd"
    assert native_connection_history("ADadiIqQiq") == "ADadiIqQ"


def test_config_rejects_repeated_once_only_markers() -> None:
    with pytest.raises(ValidationError, match="once-only"):
        TransportHistoryEntry(state="SF", weight=1, history="ShADaDadfF")


@pytest.mark.parametrize("resumed", [False, True])
def test_tls13_passive_history_never_invents_encrypted_handshake(resumed: bool) -> None:
    for seed in range(20):
        history = _choose_ssl_history_from_roll(
            random.Random(seed).random(), tls_version="TLSv13", established=True, resumed=resumed
        )
        assert history == "Cs"


def test_tls12_full_and_resumed_keep_sender_direction_and_plaintext_visibility() -> None:
    for resumed in (False, True):
        for roll in (0.0, 0.5, 0.99):
            history = _choose_ssl_history_from_roll(
                roll, tls_version="TLSv12", established=True, resumed=resumed
            )
            assert history.startswith("Cs")
            assert not set(history) & set("SXFfDd")
            assert ("x" in history and "k" in history) == (not resumed)
            assert history.index("I") < history.index("i") if not resumed else True


def test_scoped_history_override_replaces_only_selected_profile() -> None:
    default = {"ssl_histories": {"tls13_full": [1], "tls12_full": [2]}}
    merged = merge_network_params(default, {"ssl_histories": {"tls13_full": [3]}})
    assert merged["ssl_histories"] == {"tls13_full": [3], "tls12_full": [2]}
    assert default["ssl_histories"]["tls13_full"] == [1]


def test_query_bounds_do_not_admit_unknown_command_or_shell_options() -> None:
    assert _macos_foreground_lifetime("/usr/bin/id", "/usr/bin/id") == (0.008, 2.5)
    assert _macos_foreground_lifetime("/usr/bin/id", "/usr/bin/id --unknown") is None
    assert _macos_foreground_lifetime("/bin/zsh", "/bin/zsh -c 'sleep 90'") is None
    with pytest.raises(ValidationError, match="minimum <= median <= maximum"):
        ShortCommandTiming(minimum=1, median=0.5, maximum=2, sigma=0.8)
