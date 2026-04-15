# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for the config overlay merge system."""

from evidenceforge.config.overlay import deep_merge_dict, merge_keyed_list


class TestMergeKeyedList:
    """Tests for merge_keyed_list with extend-by-default and _replace flag."""

    def test_extend_list_by_default(self):
        """List fields are extended (appended) when no _replace flag is set."""
        default = [{"id": "chrome", "personas": ["developer", "analyst"], "display_name": "Chrome"}]
        overlay = [{"id": "chrome", "personas": ["nurse"]}]

        result = merge_keyed_list(default, overlay, "id")

        assert result[0]["personas"] == ["developer", "analyst", "nurse"]
        assert result[0]["display_name"] == "Chrome"

    def test_replace_list_with_replace_flag(self):
        """List fields are replaced when _replace: true is set."""
        default = [{"domain": "x.com", "tags": ["saas"], "ips": ["1.1.1.1"]}]
        overlay = [{"domain": "x.com", "tags": ["dev"], "_replace": True}]

        result = merge_keyed_list(default, overlay, "domain")

        assert result[0]["tags"] == ["dev"]
        assert result[0]["ips"] == ["1.1.1.1"]  # Unmentioned field preserved

    def test_replace_flag_stripped_from_result(self):
        """The _replace key should not appear in the merged result."""
        default = [{"domain": "x.com", "tags": ["saas"]}]
        overlay = [{"domain": "x.com", "tags": ["dev"], "_replace": True}]

        result = merge_keyed_list(default, overlay, "domain")

        assert "_replace" not in result[0]

    def test_new_entries_appended(self):
        """Overlay entries with no matching default key are appended."""
        default = [{"id": "chrome", "personas": ["developer"]}]
        overlay = [{"id": "slack", "personas": ["developer", "analyst"]}]

        result = merge_keyed_list(default, overlay, "id")

        assert len(result) == 2
        assert result[0]["id"] == "chrome"
        assert result[1]["id"] == "slack"
        assert result[1]["personas"] == ["developer", "analyst"]

    def test_new_entry_replace_flag_stripped(self):
        """_replace is stripped from new entries too."""
        default = []
        overlay = [{"id": "slack", "personas": ["developer"], "_replace": True}]

        result = merge_keyed_list(default, overlay, "id")

        assert len(result) == 1
        assert "_replace" not in result[0]

    def test_mixed_extend_and_replace(self):
        """Same overlay list can have both extending and replacing entries."""
        default = [
            {"domain": "reddit.com", "tags": ["web"], "ips": ["1.1.1.1"]},
            {"domain": "graph.ms.com", "tags": ["saas"], "ips": ["2.2.2.2"]},
        ]
        overlay = [
            {"domain": "reddit.com", "tags": ["social"]},  # extend: adds social
            {"domain": "graph.ms.com", "tags": ["dev"], "_replace": True},  # replace: dev only
        ]

        result = merge_keyed_list(default, overlay, "domain")

        reddit = next(e for e in result if e["domain"] == "reddit.com")
        graph = next(e for e in result if e["domain"] == "graph.ms.com")

        assert reddit["tags"] == ["web", "social"]  # extended
        assert graph["tags"] == ["dev"]  # replaced
        assert graph["ips"] == ["2.2.2.2"]  # preserved (unmentioned)

    def test_scalar_fields_always_replace(self):
        """Scalar fields replace regardless of _replace flag."""
        default = [{"id": "app", "display_name": "Old Name", "personas": ["dev"]}]
        overlay = [{"id": "app", "display_name": "New Name"}]

        result = merge_keyed_list(default, overlay, "id")

        assert result[0]["display_name"] == "New Name"
        assert result[0]["personas"] == ["dev"]  # list preserved (no overlay value)

    def test_unmentioned_fields_preserved_in_replace_mode(self):
        """Fields not in the overlay are preserved even with _replace: true."""
        default = [
            {
                "id": "chrome",
                "display_name": "Chrome",
                "platforms": {"windows": {"image_path": "C:\\chrome.exe"}},
                "personas": ["developer"],
                "categories": ["browser"],
            }
        ]
        overlay = [{"id": "chrome", "personas": ["nurse"], "_replace": True}]

        result = merge_keyed_list(default, overlay, "id")

        assert result[0]["personas"] == ["nurse"]  # replaced
        assert result[0]["display_name"] == "Chrome"  # preserved
        assert result[0]["categories"] == ["browser"]  # preserved
        assert result[0]["platforms"]["windows"]["image_path"] == "C:\\chrome.exe"  # preserved


class TestDeepMergeDict:
    """Tests for deep_merge_dict (used internally by merge_keyed_list)."""

    def test_lists_extend(self):
        """Lists are extended (concatenated) in deep_merge_dict."""
        default = {"a": [1, 2]}
        overlay = {"a": [3]}

        result = deep_merge_dict(default, overlay)

        assert result["a"] == [1, 2, 3]

    def test_scalars_replace(self):
        """Scalar values are replaced by overlay."""
        default = {"name": "old", "count": 5}
        overlay = {"name": "new"}

        result = deep_merge_dict(default, overlay)

        assert result["name"] == "new"
        assert result["count"] == 5

    def test_dicts_merge_recursively(self):
        """Nested dicts are merged recursively."""
        default = {"platforms": {"windows": {"path": "old"}, "linux": {"path": "/usr/bin"}}}
        overlay = {"platforms": {"windows": {"path": "new"}}}

        result = deep_merge_dict(default, overlay)

        assert result["platforms"]["windows"]["path"] == "new"
        assert result["platforms"]["linux"]["path"] == "/usr/bin"

    def test_new_keys_added(self):
        """Keys in overlay not in default are added."""
        default = {"a": 1}
        overlay = {"b": 2}

        result = deep_merge_dict(default, overlay)

        assert result == {"a": 1, "b": 2}
