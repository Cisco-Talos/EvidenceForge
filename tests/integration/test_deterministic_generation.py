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

"""Regression tests for bit-perfect generation repeatability."""

from pathlib import Path

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


def _snapshot_generated_files(root: Path) -> dict[str, bytes]:
    """Return generated file bytes keyed by stable relative path."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "generation.log"
    }


def test_minimal_generation_is_bit_perfect_for_identical_inputs(tmp_path: Path) -> None:
    """Identical scenario input should produce byte-identical generated artifacts."""
    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    scenario_data = load_yaml(scenario_path)

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    GenerationEngine(Scenario(**scenario_data), first_dir).generate()
    GenerationEngine(Scenario(**scenario_data), second_dir).generate()

    assert _snapshot_generated_files(first_dir) == _snapshot_generated_files(second_dir)


def test_public_seed_is_repeatable_and_changes_generated_evidence(tmp_path: Path) -> None:
    """One public seed controls deterministic substreams without hiding a global singleton."""
    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    scenario_data = load_yaml(scenario_path)
    first_dir = tmp_path / "seed-7-first"
    second_dir = tmp_path / "seed-7-second"
    other_dir = tmp_path / "seed-8"

    GenerationEngine(Scenario(**scenario_data), first_dir, generation_seed=7).generate()
    GenerationEngine(Scenario(**scenario_data), second_dir, generation_seed=7).generate()
    GenerationEngine(Scenario(**scenario_data), other_dir, generation_seed=8).generate()

    first = _snapshot_generated_files(first_dir)
    assert first == _snapshot_generated_files(second_dir)
    assert first != _snapshot_generated_files(other_dir)


def test_common_outputs_and_ground_truth_ignore_format_filter(tmp_path: Path) -> None:
    """Selecting fewer renderers must not change canonical planning or shared bytes."""

    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    scenario_data = load_yaml(scenario_path)
    full_scenario = Scenario(**scenario_data)
    filtered_scenario = full_scenario.model_copy(deep=True)
    filtered_scenario.output.logs = [{"format": "zeek"}]
    full_dir = tmp_path / "full"
    filtered_dir = tmp_path / "filtered"

    GenerationEngine(full_scenario, full_dir).generate()
    GenerationEngine(filtered_scenario, filtered_dir).generate()

    filtered_data = {
        str(path.relative_to(filtered_dir / "data")): path.read_bytes()
        for path in sorted((filtered_dir / "data").rglob("*"))
        if path.is_file()
    }
    full_common_data = {
        relative: (full_dir / "data" / relative).read_bytes() for relative in filtered_data
    }
    assert full_common_data == filtered_data
    assert (full_dir / "GROUND_TRUTH.json").read_bytes() == (
        filtered_dir / "GROUND_TRUTH.json"
    ).read_bytes()
