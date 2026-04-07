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

"""Tests for persona loading and merging utilities."""

import pytest

from evidenceforge.utils.personas import (
    get_builtin_personas_dir,
    load_builtin_personas,
    merge_builtin_personas,
)


@pytest.fixture
def personas_dir(tmp_path, monkeypatch):
    """Create a temp personas dir with sample YAML files."""
    d = tmp_path / "personas"
    d.mkdir()
    (d / "dev.yaml").write_text("name: developer\nrole: dev\n")
    (d / "admin.yaml").write_text("name: sysadmin\nrole: admin\n")
    monkeypatch.setattr(
        "evidenceforge.utils.personas.get_builtin_personas_dir",
        lambda: d,
    )
    return d


class TestGetBuiltinPersonasDir:
    def test_returns_personas_directory(self):
        path = get_builtin_personas_dir()
        assert path.name == "personas"
        assert path.parent.name == "config"
        assert path.is_dir()

    def test_contains_persona_yaml_files(self):
        path = get_builtin_personas_dir()
        yaml_files = list(path.glob("*.yaml"))
        assert len(yaml_files) > 0


class TestLoadBuiltinPersonas:
    def test_loads_personas_from_dir(self, personas_dir):
        personas = load_builtin_personas()
        assert len(personas) == 2

    def test_all_personas_have_name(self, personas_dir):
        for p in load_builtin_personas():
            assert "name" in p

    def test_returns_list_of_dicts(self, personas_dir):
        for p in load_builtin_personas():
            assert isinstance(p, dict)

    def test_nonexistent_dir_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "evidenceforge.utils.personas.get_builtin_personas_dir",
            lambda: tmp_path / "nonexistent",
        )
        assert load_builtin_personas() == []

    def test_skips_invalid_yaml(self, tmp_path, monkeypatch):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(":\n  - :\n  invalid: [")
        monkeypatch.setattr(
            "evidenceforge.utils.personas.get_builtin_personas_dir",
            lambda: tmp_path,
        )
        assert load_builtin_personas() == []

    def test_skips_yaml_without_name(self, tmp_path, monkeypatch):
        no_name = tmp_path / "noname.yaml"
        no_name.write_text("description: some persona without a name\n")
        monkeypatch.setattr(
            "evidenceforge.utils.personas.get_builtin_personas_dir",
            lambda: tmp_path,
        )
        assert load_builtin_personas() == []


class TestMergeBuiltinPersonas:
    def test_merges_builtin_into_empty_scenario(self, personas_dir):
        scenario = {"metadata": {"name": "test"}}
        result = merge_builtin_personas(scenario)
        assert "personas" in result
        assert len(result["personas"]) == 2

    def test_inline_personas_take_precedence(self, personas_dir):
        inline = {"name": "developer", "custom_field": "overridden"}
        scenario = {"personas": [inline]}
        result = merge_builtin_personas(scenario)
        names = [p["name"] for p in result["personas"]]

        assert names.count("developer") == 1
        match = [p for p in result["personas"] if p["name"] == "developer"][0]
        assert match.get("custom_field") == "overridden"

    def test_no_builtin_returns_unchanged(self, monkeypatch):
        monkeypatch.setattr(
            "evidenceforge.utils.personas.load_builtin_personas",
            lambda: [],
        )
        scenario = {"personas": [{"name": "inline"}]}
        result = merge_builtin_personas(scenario)
        assert result["personas"] == [{"name": "inline"}]
