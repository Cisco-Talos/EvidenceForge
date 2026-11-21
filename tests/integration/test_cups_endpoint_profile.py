# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Printer discovery locations retain their named endpoint semantics."""

import random
from copy import deepcopy
from urllib.parse import urlsplit

from evidenceforge.generation.activity.extra_syslog import (
    load_extra_syslog_messages,
    render_extra_syslog_message,
)


def _cups() -> dict:
    return deepcopy(
        next(entry for entry in load_extra_syslog_messages() if entry["app"] == "cups-browsed")
    )


def test_cups_default_endpoint_correlates_with_the_selected_printer() -> None:
    entry = _cups()
    entry["messages"] = [entry["messages"][-1]]
    for printer in entry["params"]["printer_name"]:
        rendered = render_extra_syslog_message(
            entry, random.Random(5), positional_value=981234, values={"printer_name": printer}
        )
        endpoint = urlsplit(rendered.rsplit(" at ", 1)[1])
        assert endpoint.scheme == "ipp"
        assert endpoint.hostname == printer.lower() + ".local"
        assert endpoint.port == 631 and endpoint.path == "/ipp/print"
        assert "981234" not in rendered


def test_cups_explicit_endpoint_can_preserve_a_friendly_printer_label() -> None:
    entry = _cups()
    entry["messages"] = [entry["messages"][-1]]
    entry["params"]["printer_name"] = ["Design room printer"]
    entry["params"]["printer_endpoint"] = ["ipps://print.example.test:631/printers/design"]
    rendered = render_extra_syslog_message(entry, random.Random(5), positional_value=981234)
    assert rendered.endswith("Design room printer at ipps://print.example.test:631/printers/design")


def test_frozen_legacy_printer_message_and_other_numeric_slots_keep_their_values() -> None:
    entry = _cups()
    entry["params"].pop("printer_endpoint", None)
    entry["messages"] = ["Browse remote printer {printer_name} at {}"]
    rendered = render_extra_syslog_message(entry, random.Random(5), positional_value=981234)
    assert rendered.endswith(" at 981234")
    counter = render_extra_syslog_message(
        {"messages": ["transaction /{} completed"]}, random.Random(5), positional_value=981234
    )
    assert counter == "transaction /981234 completed"
