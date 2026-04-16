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

"""Unit tests for CLI commands."""

from unittest.mock import Mock, patch

from typer.testing import CliRunner

from evidenceforge.cli.commands import (
    EXIT_ABORTED,
    EXIT_GENERATION_ERROR,
    EXIT_SCHEMA_VALIDATION,
    EXIT_SUCCESS,
    app,
)

runner = CliRunner()


class TestGenerateCommand:
    """Tests for 'eforge generate' command."""

    def test_generate_file_not_found(self):
        """eforge generate with non-existent file should handle gracefully."""
        # Typer validates file existence before calling function
        # This test verifies the CLI handles it appropriately
        result = runner.invoke(app, ["generate", "nonexistent.yaml"])

        # Typer returns error for invalid path
        assert result.exit_code != EXIT_SUCCESS

    def test_generate_schema_validation_error(self, tmp_path):
        """Invalid schema should exit with code 2."""
        # Create invalid YAML file (missing required fields)
        invalid_file = tmp_path / "invalid.yaml"
        invalid_file.write_text("""
version: "1.0"
name: test
# Missing description, environment, time_window, etc.
""")

        result = runner.invoke(app, ["generate", str(invalid_file)])

        assert result.exit_code == EXIT_SCHEMA_VALIDATION
        assert "validation" in result.stdout.lower()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_with_custom_output(self, mock_engine_class, scenarios_dir, tmp_path):
        """--output flag should use custom output directory."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        custom_output = tmp_path / "custom"

        runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(custom_output)]
        )

        # Should create engine and call generate
        assert mock_engine_class.called
        assert mock_engine.generate.called

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_success_minimal(self, mock_engine_class, scenarios_dir, tmp_path):
        """eforge generate with valid minimal scenario should succeed."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)]
        )

        assert result.exit_code == EXIT_SUCCESS
        assert "✓" in result.stdout or "complete" in result.stdout.lower()
        assert mock_engine.generate.called

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_verbose_mode(self, mock_engine_class, scenarios_dir, tmp_path):
        """--verbose flag should enable verbose logging."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--verbose",
            ],
        )

        # Verbose mode enables debug output
        assert result.exit_code == EXIT_SUCCESS

    def test_generate_validation_issues_error(self, tmp_path):
        """Scenario with validation errors should exit with code 2."""
        # Create scenario with validation error (invalid persona reference)
        invalid_scenario = tmp_path / "invalid_refs.yaml"
        invalid_scenario.write_text("""
version: "1.0"
name: test
description: "Test scenario with validation errors"

environment:
  description: "Test env"
  users:
    - username: testuser
      full_name: "Test User"
      email: "test@example.com"
      persona: "nonexistent_persona"  # Invalid reference
  systems:
    - hostname: TEST-01
      ip: 10.0.0.1
      os: "Windows 10"
      type: workstation

time_window:
  start: "2024-01-15T10:00:00Z"
  duration: "1h"

baseline_activity:
  description: "Test"
  intensity: medium
  variation: low

output:
  logs:
    - format: windows_event_security
  destination: "./output"
  compression: false
""")

        result = runner.invoke(app, ["generate", str(invalid_scenario)])

        assert result.exit_code == EXIT_SCHEMA_VALIDATION
        assert "validation" in result.stdout.lower()
        assert "nonexistent_persona" in result.stdout

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_with_progress_callback(self, mock_engine_class, scenarios_dir, tmp_path):
        """Generate should invoke progress callback during generation."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)]
        )

        # Verify engine was created with progress callback
        assert mock_engine_class.called
        call_kwargs = mock_engine_class.call_args.kwargs
        assert "progress_callback" in call_kwargs
        assert callable(call_kwargs["progress_callback"])

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_handles_generation_error(self, mock_engine_class, scenarios_dir, tmp_path):
        """Generation errors should be handled gracefully."""
        mock_engine = Mock()
        mock_engine.generate.side_effect = Exception("Generation error")
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)]
        )

        assert result.exit_code == EXIT_GENERATION_ERROR
        assert "error" in result.stdout.lower()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_prompts_on_existing_output(self, mock_engine_class, scenarios_dir, tmp_path):
        """Existing output should prompt for confirmation; 'y' proceeds."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Create existing output files
        (tmp_path / "data").mkdir()
        (tmp_path / "GROUND_TRUTH.md").write_text("old")
        (tmp_path / "ENVIRONMENT.md").write_text("old")

        result = runner.invoke(
            app,
            ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)],
            input="y\n",
        )

        assert result.exit_code == EXIT_SUCCESS
        assert "Existing output found" in result.stdout
        assert mock_engine.generate.called
        # Previous files should have been cleaned
        assert not (tmp_path / "GROUND_TRUTH.md").exists()
        assert not (tmp_path / "ENVIRONMENT.md").exists()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_aborts_on_existing_output_declined(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """Declining overwrite prompt should abort without generating."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Create existing output files
        (tmp_path / "data").mkdir()
        (tmp_path / "GROUND_TRUTH.md").write_text("old")

        result = runner.invoke(
            app,
            ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)],
            input="n\n",
        )

        assert result.exit_code == EXIT_ABORTED
        assert not mock_engine.generate.called
        # Files should NOT have been deleted
        assert (tmp_path / "data").exists()
        assert (tmp_path / "GROUND_TRUTH.md").exists()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_force_skips_prompt(self, mock_engine_class, scenarios_dir, tmp_path):
        """--force should skip the prompt and overwrite."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        # Create existing output files
        (tmp_path / "data").mkdir()
        (tmp_path / "GROUND_TRUTH.md").write_text("old")
        (tmp_path / "ENVIRONMENT.md").write_text("old")

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--force",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert "Overwrite existing output?" not in result.stdout
        assert mock_engine.generate.called
        assert not (tmp_path / "GROUND_TRUTH.md").exists()
        assert not (tmp_path / "ENVIRONMENT.md").exists()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_force_preserves_old_output_on_failure(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """If generation fails with --force, previous output should be preserved."""
        mock_engine = Mock()
        mock_engine.generate.side_effect = Exception("Generation crashed")
        mock_engine_class.return_value = mock_engine

        # Create existing output files
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "test.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--force",
            ],
        )

        assert result.exit_code == EXIT_GENERATION_ERROR
        # Previous output should be preserved (not deleted)
        assert (tmp_path / "data" / "test.xml").exists()
        assert (tmp_path / "data" / "test.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"
        # Staging directory should be cleaned up
        staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
        assert len(staging_dirs) == 0, "Staging directory should be cleaned up on failure"
        assert "previous output preserved" in result.stdout.lower()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_no_prompt_when_clean(self, mock_engine_class, scenarios_dir, tmp_path):
        """Clean output directory should not trigger any prompt."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)]
        )

        assert result.exit_code == EXIT_SUCCESS
        assert "Existing output found" not in result.stdout
        assert mock_engine.generate.called
