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

import pytest
from typer.testing import CliRunner

from evidenceforge import __version__
from evidenceforge.cli.commands import (
    EXIT_ABORTED,
    EXIT_GENERATION_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_SCHEMA_VALIDATION,
    EXIT_SUCCESS,
    app,
)
from evidenceforge.events.artifacts_manifest import ARTIFACTS_MANIFEST_FILENAME
from evidenceforge.events.observation_manifest import OBSERVATION_MANIFEST_FILENAME
from evidenceforge.output_targets import OUTPUT_TARGET_FILENAME, OutputTarget

runner = CliRunner()


def _write_included_minimal_scenario(tmp_path, *, name="include-cli-test"):
    """Write a valid minimal scenario that includes its environment section."""
    (tmp_path / "environment.yaml").write_text(
        """
environment:
  description: Included test environment
  users:
    - username: test_user
      full_name: Test User
      email: test.user@example.com
      primary_system: TEST-01
      enabled: true
  systems:
    - hostname: TEST-01
      ip: 10.0.0.1
      os: Windows 10
      type: workstation
"""
    )
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(
        f"""
includes:
  - environment.yaml
version: "1.0"
name: {name}
description: Scenario with an included environment
time_window:
  start: "2024-01-15T10:00:00Z"
  duration: "1h"
baseline_activity:
  description: Minimal baseline activity
  intensity: low
  variation: low
output:
  logs:
    - format: windows
  destination: ./output
  compression: false
"""
    )
    return scenario_file


def _write_conflicting_include_scenario(tmp_path):
    """Write a scenario whose local fields conflict with an included partial."""
    (tmp_path / "environment.yaml").write_text(
        """
environment:
  description: Included environment
"""
    )
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(
        """
includes:
  - environment.yaml
environment:
  description: Local environment
"""
    )
    return scenario_file


class TestHelpAliases:
    """Tests for CLI help option aliases."""

    @pytest.mark.parametrize(
        "args",
        [
            ["-h"],
            ["generate", "-h"],
            ["validate", "-h"],
            ["eval", "-h"],
            ["install-skills", "-h"],
            ["info", "-h"],
            ["validate-config", "-h"],
            ["version", "-h"],
        ],
    )
    def test_short_help_alias(self, args):
        """Every eforge command should accept -h as an alias for --help."""
        result = runner.invoke(app, args)

        assert result.exit_code == EXIT_SUCCESS
        assert "Usage:" in result.stdout


class TestVersionCommand:
    """Tests for 'eforge version' command."""

    def test_version_uses_package_version(self):
        """Version command should report the package version."""
        result = runner.invoke(app, ["version"])

        assert result.exit_code == EXIT_SUCCESS
        assert f"EvidenceForge v{__version__}" in result.stdout


class TestValidateCommand:
    """Tests for 'eforge validate' command."""

    def test_validate_accepts_included_environment(self, tmp_path):
        """eforge validate should expand scenario includes before schema validation."""
        scenario_file = _write_included_minimal_scenario(tmp_path)

        result = runner.invoke(app, ["validate", str(scenario_file)])

        assert result.exit_code == EXIT_SUCCESS
        assert "Schema valid: include-cli-test" in result.stdout

    def test_validate_reports_include_conflict_as_schema_validation(self, tmp_path):
        """eforge validate should treat include conflicts as validation errors."""
        scenario_file = _write_conflicting_include_scenario(tmp_path)

        result = runner.invoke(app, ["validate", str(scenario_file)])

        assert result.exit_code == EXIT_SCHEMA_VALIDATION
        assert "Scenario include validation failed" in result.stdout
        assert "environment.description" in result.stdout


class TestEvalCommand:
    """Tests for 'eforge eval' command."""

    def test_eval_accepts_included_environment(self, tmp_path):
        """eforge eval should expand scenario includes before constructing the evaluator."""
        output_dir = tmp_path / "data"
        output_dir.mkdir()
        scenario_file = _write_included_minimal_scenario(tmp_path, name="include-eval-test")

        with (
            patch("evidenceforge.evaluation.engine.EvaluationEngine") as mock_engine_class,
            patch("evidenceforge.evaluation.report.format_text_report") as mock_format_text,
        ):
            mock_report = Mock()
            mock_engine_class.return_value.run.return_value = mock_report

            result = runner.invoke(
                app,
                [
                    "eval",
                    str(output_dir),
                    "--scenario",
                    str(scenario_file),
                ],
            )

        assert result.exit_code == EXIT_SUCCESS
        assert mock_engine_class.called
        assert mock_engine_class.call_args.kwargs["scenario"].name == "include-eval-test"
        mock_format_text.assert_called_once()
        assert mock_format_text.call_args.args[0] is mock_report

    def test_eval_reports_include_conflict_as_schema_validation(self, tmp_path):
        """eforge eval should treat include conflicts as scenario validation errors."""
        output_dir = tmp_path / "data"
        output_dir.mkdir()
        scenario_file = _write_conflicting_include_scenario(tmp_path)

        result = runner.invoke(app, ["eval", str(output_dir), "--scenario", str(scenario_file)])

        assert result.exit_code == EXIT_SCHEMA_VALIDATION
        assert "Scenario include validation failed" in result.stdout
        assert "environment.description" in result.stdout


class TestGenerateCommand:
    """Tests for 'eforge generate' command."""

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_accepts_included_environment(self, mock_engine_class, tmp_path):
        """eforge generate should expand scenario includes before constructing the engine."""
        scenario_file = _write_included_minimal_scenario(tmp_path, name="include-generate-test")

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenario_file),
                "--output",
                str(tmp_path / "out"),
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert mock_engine_class.called
        assert mock_engine_class.call_args.kwargs["scenario"].name == "include-generate-test"
        assert mock_engine_class.return_value.generate.called

    def test_generate_reports_include_conflict_as_schema_validation(self, tmp_path):
        """eforge generate should treat include conflicts as scenario validation errors."""
        scenario_file = _write_conflicting_include_scenario(tmp_path)

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenario_file),
                "--output",
                str(tmp_path / "out"),
            ],
        )

        assert result.exit_code == EXIT_SCHEMA_VALIDATION
        assert "Scenario include validation failed" in result.stdout
        assert "environment.description" in result.stdout

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
        assert mock_engine_class.call_args.kwargs["output_target"] == OutputTarget.DEFAULT

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_accepts_sof_elk_target(self, mock_engine_class, scenarios_dir, tmp_path):
        """--target sof-elk is passed to the generation engine."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--target",
                "sof-elk",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert mock_engine_class.call_args.kwargs["output_target"] == OutputTarget.SOF_ELK
        assert (tmp_path / OUTPUT_TARGET_FILENAME).read_text(encoding="utf-8") == "sof-elk\n"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_accepts_splunk_target(self, mock_engine_class, scenarios_dir, tmp_path):
        """--target splunk is passed to the generation engine."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--target",
                "splunk",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert mock_engine_class.call_args.kwargs["output_target"] == OutputTarget.SPLUNK
        assert (tmp_path / OUTPUT_TARGET_FILENAME).read_text(encoding="utf-8") == "splunk\n"

    def test_generate_invalid_target_fails_clearly(self, scenarios_dir, tmp_path):
        """Invalid --target values should fail before generation starts."""
        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--target",
                "not-a-target",
            ],
        )

        assert result.exit_code == EXIT_INPUT_ERROR
        assert "invalid output target" in result.stdout

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
    def test_generate_rejects_dangling_generated_report_symlink(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """Dangling generated report symlinks should be rejected before generation."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        ground_truth = tmp_path / "GROUND_TRUTH.md"
        outside_target = tmp_path / "outside-ground-truth.md"
        try:
            ground_truth.symlink_to(outside_target)
        except OSError as exc:
            pytest.skip(f"Symlink creation unsupported in this environment: {exc}")

        result = runner.invoke(
            app, ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)]
        )

        assert result.exit_code == EXIT_INPUT_ERROR
        assert "symlink" in result.stdout.lower()
        assert not mock_engine.generate.called
        assert ground_truth.is_symlink()
        assert not outside_target.exists()

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

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')
                (sd / ARTIFACTS_MANIFEST_FILENAME).write_text(
                    '{"schema_version": "1.0", "email": {"messages": [{"message_id": "new"}]}}'
                )

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
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
        assert (tmp_path / "GROUND_TRUTH.json").exists()
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "new ground truth"
        # ENVIRONMENT.md is authored by /eforge scenario, not the engine — must be preserved
        assert (tmp_path / "ENVIRONMENT.md").exists()
        assert (tmp_path / "ENVIRONMENT.md").read_text() == "old"

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
    def test_generate_prompts_on_existing_artifacts_manifest(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """A root artifact manifest is generated output and should be overwrite-protected."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        (tmp_path / ARTIFACTS_MANIFEST_FILENAME).write_text(
            '{"schema_version": "1.0", "email": {"messages": []}}'
        )

        result = runner.invoke(
            app,
            ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path)],
            input="n\n",
        )

        assert result.exit_code == EXIT_ABORTED
        assert ARTIFACTS_MANIFEST_FILENAME in result.stdout
        assert not mock_engine.generate.called
        assert (tmp_path / ARTIFACTS_MANIFEST_FILENAME).exists()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_force_skips_prompt(self, mock_engine_class, scenarios_dir, tmp_path):
        """--force should skip the prompt and overwrite."""

        def _fake_generate():
            # Simulate engine creating staged output in the staging dir
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        # Create existing output files
        (tmp_path / "data").mkdir()
        (tmp_path / "GROUND_TRUTH.md").write_text("old")
        (tmp_path / OBSERVATION_MANIFEST_FILENAME).write_text("old manifest")
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
        assert (tmp_path / "GROUND_TRUTH.json").exists()
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "new ground truth"
        assert (tmp_path / OBSERVATION_MANIFEST_FILENAME).read_text() == '{"schema_version": 1}'
        assert (tmp_path / "data" / "new.xml").read_text() == "new data"
        # ENVIRONMENT.md must be preserved (not engine output)
        assert (tmp_path / "ENVIRONMENT.md").exists()
        assert (tmp_path / "ENVIRONMENT.md").read_text() == "old"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_partial_prior_state_rollback_keeps_matched_set(
        self, mock_engine_class, scenarios_dir, tmp_path, monkeypatch
    ):
        """A swap failure must not leave a NEW GROUND_TRUTH.md orphaned over restored
        OLD data/ when the prior output was partial (data/ but no GT.md). Rollback
        strips the just-installed new artifacts unconditionally, restoring the
        matched set (here: old data/, still no GT.md)."""
        from pathlib import Path

        def _fake_generate():
            sd = next(iter(tmp_path.glob(".eforge_staging_*")))
            (sd / "data").mkdir(exist_ok=True)
            (sd / "data" / "new.xml").write_text("new data")
            (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
            (sd / "GROUND_TRUTH.md").write_text("new ground truth")
            (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        # PARTIAL prior state: data/ exists, but GROUND_TRUTH.md does NOT.
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")

        # Force a failure at the LAST install step (the OUTPUT_TARGET marker) so the
        # swap fails AFTER new data/ + new GROUND_TRUTH.md were already installed.
        real_rename = Path.rename

        def boom_rename(self, target):
            if self.name == OUTPUT_TARGET_FILENAME and ".eforge_staging_" in str(self):
                raise RuntimeError("injected swap failure")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", boom_rename)

        result = runner.invoke(
            app,
            ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path), "--force"],
        )

        assert result.exit_code != EXIT_SUCCESS  # the run failed
        # No orphaned NEW ground truth, and the OLD data/ is restored intact.
        assert not (tmp_path / "GROUND_TRUTH.md").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert not (tmp_path / "data" / "new.xml").exists()

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_generate_force_baseline_only_replaces_complete_report_set(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """--force should swap baseline-only outputs with data, reports, and manifest."""

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "baseline.log").write_text("new baseline data")
                (sd / "GROUND_TRUTH.json").write_text(
                    '{"schema_version": 1, "scenario_name": "baseline-only", "events": []}'
                )
                (sd / "GROUND_TRUTH.md").write_text(
                    "# Ground Truth: baseline-only\n\n*No malicious activities in this scenario.*\n"
                )
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text(
                    '{"schema_version": 1, "scenario_name": "baseline-only"}'
                )
                (sd / ARTIFACTS_MANIFEST_FILENAME).write_text(
                    '{"schema_version": "1.0", "email": {"messages": [{"message_id": "new"}]}}'
                )
                (sd / "artifacts" / "email").mkdir(parents=True)
                (sd / "artifacts" / "email" / "new.eml").write_text("new artifact")

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.log").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")
        (tmp_path / OBSERVATION_MANIFEST_FILENAME).write_text("old manifest")
        (tmp_path / ARTIFACTS_MANIFEST_FILENAME).write_text("old artifacts manifest")
        (tmp_path / "artifacts" / "email").mkdir(parents=True)
        (tmp_path / "artifacts" / "email" / "old.eml").write_text("old artifact")
        (tmp_path / "ENVIRONMENT.md").write_text("scenario-authored")

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "baseline-only.yaml"),
                "--output",
                str(tmp_path),
                "--force",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert not (tmp_path / "data" / "old.log").exists()
        assert (tmp_path / "data" / "baseline.log").read_text() == "new baseline data"
        assert "baseline-only" in (tmp_path / "GROUND_TRUTH.json").read_text()
        assert "No malicious activities" in (tmp_path / "GROUND_TRUTH.md").read_text()
        assert "baseline-only" in (tmp_path / OBSERVATION_MANIFEST_FILENAME).read_text()
        assert "message_id" in (tmp_path / ARTIFACTS_MANIFEST_FILENAME).read_text()
        assert not (tmp_path / "artifacts" / "email" / "old.eml").exists()
        assert (tmp_path / "artifacts" / "email" / "new.eml").read_text() == "new artifact"
        assert (tmp_path / "ENVIRONMENT.md").read_text() == "scenario-authored"

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
    def test_force_swap_restores_on_data_install_failure(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """If installing new data/ fails, old data + old GT must be restored as a pair."""
        from pathlib import Path

        original_rename = Path.rename

        def _fail_on_data_install(self_path, target):
            if (
                self_path.name == "data"
                and target.name == "data"
                and "rollback" not in str(self_path)
            ):
                # Fail when installing staged data/ → live data/
                if ".eforge_staging_" in str(self_path):
                    raise OSError("Simulated disk error during data install")
            return original_rename(self_path, target)

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")
        (tmp_path / ARTIFACTS_MANIFEST_FILENAME).write_text("old artifacts manifest")

        with patch.object(Path, "rename", _fail_on_data_install):
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
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"
        assert (tmp_path / ARTIFACTS_MANIFEST_FILENAME).read_text() == "old artifacts manifest"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_restores_on_gt_install_failure(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """If installing new GROUND_TRUTH.md fails (after data succeeds), both old files restored."""
        from pathlib import Path

        original_rename = Path.rename
        data_installed = []

        def _fail_on_gt_install(self_path, target):
            if self_path.name == "GROUND_TRUTH.md" and "staging" in str(self_path):
                raise OSError("Simulated disk error during GT install")
            result = original_rename(self_path, target)
            if self_path.name == "data" and ".eforge_staging_" in str(self_path):
                data_installed.append(True)
            return result

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")

        with patch.object(Path, "rename", _fail_on_gt_install):
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
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_verifies_staged_data_exists(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """If engine succeeds but staged data/ is missing, old output must be preserved."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        # Engine "succeeds" but doesn't create staged data/

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")

        result = runner.invoke(
            app,
            ["generate", str(scenarios_dir / "minimal.yaml"), "--output", str(tmp_path), "--force"],
        )

        assert result.exit_code == EXIT_GENERATION_ERROR
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_restores_on_keyboard_interrupt(
        self, mock_engine_class, scenarios_dir, tmp_path
    ):
        """KeyboardInterrupt during swap must restore old output."""
        from pathlib import Path

        original_rename = Path.rename

        def _interrupt_on_data_install(self_path, target):
            if self_path.name == "data" and ".eforge_staging_" in str(self_path):
                raise KeyboardInterrupt()
            return original_rename(self_path, target)

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")

        with patch.object(Path, "rename", _interrupt_on_data_install):
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

        # KeyboardInterrupt → exit code for SIGINT
        assert result.exit_code != EXIT_SUCCESS
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_requires_staged_gt(self, mock_engine_class, scenarios_dir, tmp_path):
        """If engine succeeds but staged GROUND_TRUTH.md is missing, old output preserved."""

        def _fake_generate_no_gt():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                # Deliberately skip creating GROUND_TRUTH.md

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate_no_gt
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
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
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_requires_staged_manifest(self, mock_engine_class, scenarios_dir, tmp_path):
        """If engine succeeds but staged observation manifest is missing, old output preserved."""

        def _fake_generate_no_manifest():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                # Deliberately skip creating OBSERVATION_MANIFEST.json

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate_no_manifest
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")
        (tmp_path / OBSERVATION_MANIFEST_FILENAME).write_text("old manifest")

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
        assert (tmp_path / "data" / "old.xml").exists()
        assert (tmp_path / "data" / "old.xml").read_text() == "old data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "old ground truth"
        assert (tmp_path / OBSERVATION_MANIFEST_FILENAME).read_text() == "old manifest"

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_force_swap_cleans_stale_rollback(self, mock_engine_class, scenarios_dir, tmp_path):
        """Stale rollback dirs from prior killed runs are cleaned up."""

        def _fake_generate():
            staging_dirs = list(tmp_path.glob(".eforge_staging_*"))
            if staging_dirs:
                sd = staging_dirs[0]
                (sd / "data").mkdir(exist_ok=True)
                (sd / "data" / "new.xml").write_text("new data")
                (sd / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "events": []}')
                (sd / "GROUND_TRUTH.md").write_text("new ground truth")
                (sd / OBSERVATION_MANIFEST_FILENAME).write_text('{"schema_version": 1}')

        mock_engine = Mock()
        mock_engine.generate.side_effect = _fake_generate
        mock_engine_class.return_value = mock_engine

        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "old.xml").write_text("old data")
        (tmp_path / "GROUND_TRUTH.md").write_text("old ground truth")

        # Simulate stale rollback dir from a prior killed run
        stale_dir = tmp_path / ".eforge_rollback_stale123"
        stale_dir.mkdir()
        (stale_dir / "data").mkdir()
        (stale_dir / "data" / "ancient.xml").write_text("ancient data")

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
        assert (tmp_path / "data" / "new.xml").read_text() == "new data"
        assert (tmp_path / "GROUND_TRUTH.md").read_text() == "new ground truth"
        # Stale rollback dir should be cleaned up
        assert not stale_dir.exists()
        # No rollback dirs should remain
        assert len(list(tmp_path.glob(".eforge_rollback_*"))) == 0

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

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_formats_flag_filters_output(self, mock_engine_class, scenarios_dir, tmp_path):
        """--formats should narrow scenario output.logs to the intersection."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--formats",
                "zeek_conn",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        # Engine should have been created with narrowed format list
        call_kwargs = mock_engine_class.call_args.kwargs
        scenario = call_kwargs["scenario"]
        fmt_names = {log["format"] for log in scenario.output.logs}
        assert fmt_names == {"zeek_conn"}

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_formats_flag_supports_groups(self, mock_engine_class, scenarios_dir, tmp_path):
        """--formats should expand group names before intersecting."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--formats",
                "zeek",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        call_kwargs = mock_engine_class.call_args.kwargs
        scenario = call_kwargs["scenario"]
        fmt_names = {log["format"] for log in scenario.output.logs}
        assert "zeek_conn" in fmt_names
        assert "zeek_dns" in fmt_names
        # Windows should NOT be in the output
        assert "windows_event_security" not in fmt_names

    @patch("evidenceforge.cli.commands.GenerationEngine")
    def test_formats_flag_warns_on_mismatch(self, mock_engine_class, scenarios_dir, tmp_path):
        """--formats with formats not in scenario should warn."""
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--formats",
                "zeek_conn,cisco_asa",
            ],
        )

        assert result.exit_code == EXIT_SUCCESS
        assert "not in scenario" in result.stdout
        assert "cisco_asa" in result.stdout

    def test_formats_flag_errors_on_empty_intersection(self, scenarios_dir, tmp_path):
        """--formats with no matching formats should error."""
        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "minimal.yaml"),
                "--output",
                str(tmp_path),
                "--formats",
                "cisco_asa",
            ],
        )

        assert result.exit_code == EXIT_INPUT_ERROR
        assert "No formats match" in result.stdout
