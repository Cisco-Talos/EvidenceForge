"""Unit tests for CLI commands."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import (
    EXIT_GENERATION_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_SCHEMA_VALIDATION,
    EXIT_SUCCESS,
    app,
)

runner = CliRunner()


class TestInitCommand:
    """Tests for 'eforge init' command."""

    def test_init_creates_config(self, tmp_path, monkeypatch):
        """eforge init should create config.yaml in current directory."""
        monkeypatch.chdir(tmp_path)

        # Create config.example.yaml in tmp_path
        example_config = tmp_path / "config.example.yaml"
        example_config.write_text("""
aws:
  profile: default
  region: us-east-1

bedrock:
  model_id: anthropic.claude-sonnet-4-6
  max_tokens: 4096
  temperature: 1.0

output:
  buffer_size: 10000

logging:
  level: INFO
  file: null
""")

        result = runner.invoke(app, ["init"])

        assert result.exit_code == EXIT_SUCCESS
        assert (tmp_path / "config.yaml").exists()
        assert "Created" in result.stdout

        # Verify config file has expected content
        config = yaml.safe_load((tmp_path / "config.yaml").read_text())
        assert "aws" in config
        assert "bedrock" in config

    def test_init_with_existing_config(self, tmp_path, monkeypatch):
        """eforge init should handle existing config.yaml gracefully."""
        monkeypatch.chdir(tmp_path)

        # Create config.example.yaml
        example_config = tmp_path / "config.example.yaml"
        example_config.write_text("test: config\n")

        # Create existing config
        existing_config = tmp_path / "config.yaml"
        existing_config.write_text("existing: content\n")

        result = runner.invoke(app, ["init"])

        # Should exit successfully but not overwrite (without --force)
        assert result.exit_code == EXIT_SUCCESS
        assert existing_config.exists()
        assert "already exists" in result.stdout.lower()


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

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_with_custom_output(self, mock_engine_class, scenarios_dir, tmp_path):
        """--output flag should use custom output directory."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        custom_output = tmp_path / "custom"

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--output", str(custom_output)
        ])

        # Should create engine and call generate
        assert mock_engine_class.called
        assert mock_engine.generate.called

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_with_config_flag(self, mock_engine_class, scenarios_dir, tmp_path):
        """--config flag should load custom config file."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        config_file = tmp_path / "custom_config.yaml"
        config_file.write_text("""
aws:
  profile: test
  region: us-west-2
bedrock:
  model_id: anthropic.claude-sonnet-4-6
output:
  buffer_size: 5000
logging:
  level: DEBUG
""")

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--config", str(config_file),
            "--output", str(tmp_path / "out")
        ])

        # Should succeed (config loaded)
        assert result.exit_code == EXIT_SUCCESS

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_success_minimal(self, mock_engine_class, scenarios_dir, tmp_path):
        """eforge generate with valid minimal scenario should succeed."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--output", str(tmp_path)
        ])

        assert result.exit_code == EXIT_SUCCESS
        assert "✓" in result.stdout or "complete" in result.stdout.lower()
        assert mock_engine.generate.called

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_verbose_mode(self, mock_engine_class, scenarios_dir, tmp_path):
        """--verbose flag should enable verbose logging."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--output", str(tmp_path),
            "--verbose"
        ])

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

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_with_progress_callback(self, mock_engine_class, scenarios_dir, tmp_path):
        """Generate should invoke progress callback during generation."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--output", str(tmp_path)
        ])

        # Verify engine was created with progress callback
        assert mock_engine_class.called
        call_kwargs = mock_engine_class.call_args.kwargs
        assert 'progress_callback' in call_kwargs
        assert callable(call_kwargs['progress_callback'])

    @patch('evidenceforge.cli.commands.GenerationEngine')
    def test_generate_handles_generation_error(self, mock_engine_class, scenarios_dir, tmp_path):
        """Generation errors should be handled gracefully."""
        mock_engine = Mock()
        mock_engine.generate.side_effect = Exception("Generation error")
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(app, [
            "generate",
            str(scenarios_dir / "minimal.yaml"),
            "--output", str(tmp_path)
        ])

        assert result.exit_code == EXIT_GENERATION_ERROR
        assert "error" in result.stdout.lower()
