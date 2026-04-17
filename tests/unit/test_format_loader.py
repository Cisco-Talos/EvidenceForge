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

"""Unit tests for format definition loader."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from evidenceforge.formats.format_def import (
    FieldDefinition,
    FieldType,
    FormatDefinition,
    OutputTemplate,
)
from evidenceforge.formats.loader import (
    clear_cache,
    get_definitions_directory,
    get_format,
    load_all_formats,
    load_format,
)
from evidenceforge.models.exceptions import ConfigurationError


class TestGetDefinitionsDirectory:
    """Tests for get_definitions_directory function."""

    def test_returns_path(self):
        """Test that function returns a Path object."""
        result = get_definitions_directory()
        assert isinstance(result, Path)

    def test_path_is_absolute(self):
        """Test that returned path is absolute."""
        result = get_definitions_directory()
        assert result.is_absolute()

    def test_path_ends_with_formats(self):
        """Test that path ends with config/formats."""
        result = get_definitions_directory()
        assert result.name == "formats"
        assert result.parent.name == "config"

    def test_raises_error_if_not_exists(self, tmp_path):
        """Test that error is raised if directory doesn't exist."""
        fake_dir = tmp_path / "nonexistent"

        with patch(
            "evidenceforge.formats.loader.get_formats_directory",
            side_effect=ConfigurationError(f"Format definitions directory not found: {fake_dir}"),
        ):
            with pytest.raises(ConfigurationError, match="not found"):
                get_definitions_directory()


class TestClearCache:
    """Tests for clear_cache function."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def test_clears_empty_cache(self):
        """Test that clearing empty cache doesn't error."""
        clear_cache()
        assert get_format("nonexistent") is None

    def test_clears_populated_cache(self):
        """Test that clearing populated cache removes entries."""
        # Create a mock format and add it to cache manually
        mock_format = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="f", type=FieldType.STRING)],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )

        # Import the cache directly to populate it
        from evidenceforge.formats import loader

        loader._format_cache["test"] = mock_format

        # Verify it's in cache
        assert get_format("test") is not None

        # Clear cache
        clear_cache()

        # Verify it's gone
        assert get_format("test") is None


class TestGetFormat:
    """Tests for get_format function."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def test_returns_none_for_missing_format(self):
        """Test that None is returned for uncached format."""
        result = get_format("nonexistent")
        assert result is None

    def test_returns_cached_format(self):
        """Test that cached format is returned."""
        # Create a mock format and add it to cache
        mock_format = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="f", type=FieldType.STRING)],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )

        from evidenceforge.formats import loader

        loader._format_cache["test"] = mock_format

        # Get format
        result = get_format("test")

        # Verify it's the same object
        assert result is mock_format
        assert result.name == "test"


class TestLoadFormat:
    """Tests for load_format function."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def teardown_method(self):
        """Clear cache after each test."""
        clear_cache()

    def test_raises_error_for_missing_file(self):
        """Test that ConfigurationError is raised for non-existent file."""
        with pytest.raises(ConfigurationError, match="not found"):
            load_format("nonexistent_format")

    @pytest.mark.parametrize(
        "invalid_name",
        ["../malicious", "..\\malicious", "/tmp/malicious", "nested/name", "host;rm -rf /"],
    )
    def test_rejects_unsafe_format_names(self, invalid_name):
        """Path traversal and unsafe characters in format names are rejected."""
        with pytest.raises(ConfigurationError, match="Invalid format definition name"):
            load_format(invalid_name)

    def test_file_path_in_error_message(self):
        """Test that error message contains file path."""
        try:
            load_format("nonexistent_format")
        except ConfigurationError as e:
            error_msg = str(e)
            assert "nonexistent_format" in error_msg
            assert ".yaml" in error_msg

    @patch("evidenceforge.formats.loader.load_yaml")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_invalid_yaml_raises_error(self, mock_get_dir, mock_load_yaml):
        """Test that invalid YAML raises ConfigurationError."""
        # Mock the directory to exist
        mock_dir = MagicMock()
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_file.__str__.return_value = "/fake/path/invalid.yaml"
        mock_dir.__truediv__.return_value = mock_file
        mock_get_dir.return_value = mock_dir

        # Mock load_yaml to return invalid data
        mock_load_yaml.return_value = {
            "name": "test",
            "description": "Test",
            "category": "invalid_category",  # This will fail validation
            "fields": [],
            "output": {"format": "xml", "template": "t", "file_extension": ".xml"},
        }

        with pytest.raises(ConfigurationError, match="Invalid format definition"):
            load_format("test")

    @patch("evidenceforge.formats.loader.load_yaml")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_load_valid_format(self, mock_get_dir, mock_load_yaml):
        """Test loading a valid format definition."""
        # Mock the directory
        mock_dir = MagicMock()
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_dir.__truediv__.return_value = mock_file
        mock_get_dir.return_value = mock_dir

        # Mock load_yaml to return valid data
        mock_load_yaml.return_value = {
            "name": "test_format",
            "version": "1.0",
            "description": "Test",
            "category": "host",
            "fields": [{"name": "field1", "type": "string", "required": True}],
            "output": {
                "format": "text",
                "template": "test",
                "file_extension": ".txt",
            },
        }

        # Load format
        result = load_format("test_format")

        # Verify result
        assert isinstance(result, FormatDefinition)
        assert result.name == "test_format"
        assert result.category == "host"
        assert len(result.fields) == 1

    @patch("evidenceforge.formats.loader.load_yaml")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_caching_works(self, mock_get_dir, mock_load_yaml):
        """Test that second load uses cache."""
        # Mock the directory
        mock_dir = MagicMock()
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_dir.__truediv__.return_value = mock_file
        mock_get_dir.return_value = mock_dir

        # Mock load_yaml
        mock_load_yaml.return_value = {
            "name": "test_format",
            "version": "1.0",
            "description": "Test",
            "category": "host",
            "fields": [{"name": "f", "type": "string"}],
            "output": {"format": "text", "template": "t", "file_extension": ".txt"},
        }

        # First load
        result1 = load_format("test_format")

        # Reset mock to verify it's not called again
        mock_load_yaml.reset_mock()

        # Second load (should use cache)
        result2 = load_format("test_format")

        # Verify load_yaml was not called second time
        mock_load_yaml.assert_not_called()

        # Verify both results are the same object
        assert result1 is result2

    @patch("evidenceforge.formats.loader.load_yaml")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_force_reload_bypasses_cache(self, mock_get_dir, mock_load_yaml):
        """Test that force_reload=True bypasses cache."""
        # Mock the directory
        mock_dir = MagicMock()
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_dir.__truediv__.return_value = mock_file
        mock_get_dir.return_value = mock_dir

        # Mock load_yaml
        mock_load_yaml.return_value = {
            "name": "test_format",
            "version": "1.0",
            "description": "Test",
            "category": "host",
            "fields": [{"name": "f", "type": "string"}],
            "output": {"format": "text", "template": "t", "file_extension": ".txt"},
        }

        # First load
        load_format("test_format")

        # Reset mock
        mock_load_yaml.reset_mock()

        # Second load with force_reload
        load_format("test_format", force_reload=True)

        # Verify load_yaml WAS called again
        mock_load_yaml.assert_called_once()


class TestLoadAllFormats:
    """Tests for load_all_formats function."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def teardown_method(self):
        """Clear cache after each test."""
        clear_cache()

    @patch("evidenceforge.formats.loader.load_format")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_empty_directory_returns_empty_dict(self, mock_get_dir, mock_load):
        """Test that empty directory returns empty dict."""
        mock_dir = MagicMock()
        mock_dir.glob.return_value = []
        mock_get_dir.return_value = mock_dir

        result = load_all_formats()

        assert result == {}
        mock_load.assert_not_called()

    @patch("evidenceforge.formats.loader.load_format")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_loads_all_yaml_files(self, mock_get_dir, mock_load):
        """Test that all YAML files are loaded."""
        # Mock directory with multiple files
        mock_file1 = MagicMock()
        mock_file1.stem = "format1"
        mock_file2 = MagicMock()
        mock_file2.stem = "format2"

        mock_dir = MagicMock()
        mock_dir.glob.return_value = [mock_file1, mock_file2]
        mock_get_dir.return_value = mock_dir

        # Mock load_format to return mock formats
        mock_fmt1 = MagicMock()
        mock_fmt1.name = "format1"
        mock_fmt2 = MagicMock()
        mock_fmt2.name = "format2"

        mock_load.side_effect = [mock_fmt1, mock_fmt2]

        # Load all formats
        result = load_all_formats()

        # Verify results
        assert len(result) == 2
        assert "format1" in result
        assert "format2" in result
        assert mock_load.call_count == 2

    @patch("evidenceforge.formats.loader.load_format")
    @patch("evidenceforge.formats.loader.get_definitions_directory")
    def test_error_in_one_format_stops_loading(self, mock_get_dir, mock_load):
        """Test that error in one format raises and stops loading."""
        # Mock directory with files
        mock_file1 = MagicMock()
        mock_file1.stem = "format1"
        mock_file2 = MagicMock()
        mock_file2.stem = "format2"

        mock_dir = MagicMock()
        mock_dir.glob.return_value = [mock_file1, mock_file2]
        mock_get_dir.return_value = mock_dir

        # Mock load_format to raise error on first format
        mock_load.side_effect = ConfigurationError("Test error")

        # Should raise error
        with pytest.raises(ConfigurationError, match="Test error"):
            load_all_formats()
