# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for path safety utilities."""

import pytest

from evidenceforge.utils.paths import reject_symlink, safe_path_join, sanitize_path_component


class TestSanitizePathComponent:
    """Tests for sanitize_path_component."""

    def test_valid_hostname(self):
        assert sanitize_path_component("web-server-01.corp.local") == "web-server-01.corp.local"

    def test_valid_simple(self):
        assert sanitize_path_component("DC01") == "DC01"

    def test_valid_with_dots(self):
        assert sanitize_path_component("host.domain.com") == "host.domain.com"

    def test_rejects_empty(self):
        assert sanitize_path_component("") == ""
        assert sanitize_path_component("   ") == ""

    def test_rejects_path_traversal_unix(self):
        assert sanitize_path_component("../../etc/passwd") == ""

    def test_rejects_path_traversal_windows(self):
        assert sanitize_path_component("..\\..\\Windows\\System32") == ""

    def test_rejects_forward_slash(self):
        assert sanitize_path_component("host/child") == ""

    def test_rejects_backslash(self):
        assert sanitize_path_component("host\\child") == ""

    def test_rejects_dotdot(self):
        assert sanitize_path_component("..") == ""

    def test_rejects_dotdot_in_name(self):
        assert sanitize_path_component("host..evil") == ""

    def test_rejects_special_characters(self):
        assert sanitize_path_component("host;rm -rf /") == ""
        assert sanitize_path_component("host$(whoami)") == ""

    def test_strips_whitespace(self):
        assert sanitize_path_component("  host.local  ") == "host.local"


class TestSafePathJoin:
    """Tests for safe_path_join."""

    def test_valid_join(self, tmp_path):
        base = tmp_path / "output"
        base.mkdir()
        result = safe_path_join(base, "host.local", "logs")
        assert result is not None
        assert str(result).startswith(str(base))

    def test_rejects_traversal(self, tmp_path):
        base = tmp_path / "output"
        base.mkdir()
        result = safe_path_join(base, "../../escape")
        assert result is None

    def test_rejects_unsafe_component(self, tmp_path):
        base = tmp_path / "output"
        base.mkdir()
        result = safe_path_join(base, "host/evil")
        assert result is None

    def test_multiple_components(self, tmp_path):
        base = tmp_path / "output"
        base.mkdir()
        result = safe_path_join(base, "host.local", "windows")
        assert result is not None
        assert result == base / "host.local" / "windows"


class TestRejectSymlink:
    """Tests for reject_symlink."""

    def test_accepts_regular_directory(self, tmp_path):
        d = tmp_path / "normal"
        d.mkdir()
        reject_symlink(d)  # Should not raise

    def test_accepts_nonexistent(self, tmp_path):
        d = tmp_path / "nonexistent"
        reject_symlink(d)  # Should not raise

    def test_rejects_symlink(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(PermissionError, match="symlinked path"):
            reject_symlink(link)

    def test_rejects_dangling_symlink(self, tmp_path):
        link = tmp_path / "dangling"
        link.symlink_to(tmp_path / "nonexistent")
        with pytest.raises(PermissionError, match="symlinked path"):
            reject_symlink(link)
