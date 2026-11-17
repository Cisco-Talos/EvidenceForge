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

"""Authored observation overrides accept exactly the source families the catalog defines."""

from typing import get_args

import pytest
from pydantic import ValidationError

from evidenceforge.events.source_catalog import (
    DEFAULT_SOURCE_CATALOG,
    SourceCatalogError,
    SourceOwnerKind,
    _host,
)
from evidenceforge.models import scenario as model
from evidenceforge.models.scenario import Scenario
from evidenceforge.source_families import SOURCE_FORMATS


def test_catalog_and_scenario_vocabulary_share_one_source_table() -> None:
    assert {
        name: (descriptor.family, descriptor.owner.value)
        for name in DEFAULT_SOURCE_CATALOG.format_names
        for descriptor in (DEFAULT_SOURCE_CATALOG.descriptor(name),)
    } == dict(SOURCE_FORMATS)
    assert get_args(model.ObservationFormatName) == tuple(SOURCE_FORMATS)
    assert set(get_args(model.ObservationSourceFamily)) == {
        family for family, _owner in SOURCE_FORMATS.values()
    }
    assert dict(model._OBSERVATION_FORMAT_FAMILIES) == {
        name: family for name, (family, _owner) in SOURCE_FORMATS.items()
    }


def test_catalog_rejects_formats_missing_from_the_source_table() -> None:
    with pytest.raises(SourceCatalogError, match="SOURCE_FORMATS"):
        _host(
            "unlisted_format", DEFAULT_SOURCE_CATALOG.descriptor("ecar").capabilities, frozenset()
        )
    assert SOURCE_FORMATS["zeek_conn"][1] == SourceOwnerKind.SENSOR.value


def _mac_scenario_with(override: dict) -> Scenario:
    from tests.unit.test_macos_installed_provisioning import _scenario

    document = _scenario().model_dump(mode="json", exclude_none=True)
    document["environment"]["observation_overrides"] = [override]
    document["macos_process_coverage"] = "partial"
    return Scenario.model_validate(document)


@pytest.mark.parametrize("family", ["macos_endpoint_security", "macos_unified_log"])
def test_authored_macos_observation_override_is_accepted(family: str) -> None:
    scenario = _mac_scenario_with(
        {"source_instance": f"{family}:mac-01", "family": family, "enabled": False}
    )

    (override,) = scenario.environment.observation_overrides
    assert override.source_instance == f"{family}:mac-01"


def test_macos_observation_override_still_requires_a_known_host() -> None:
    with pytest.raises(ValidationError, match="unknown source instances"):
        _mac_scenario_with({"source_instance": "macos_endpoint_security:mac-99", "enabled": False})
