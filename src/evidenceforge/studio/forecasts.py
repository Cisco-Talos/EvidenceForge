"""Revision-bound resource prediction through a disposable deterministic CLI process."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from evidenceforge import __version__
from evidenceforge.desktop.jobs import _eforge_command
from evidenceforge.resources import ResourcePrediction
from evidenceforge.studio.jobs import controller_settings
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.studio.store import CatalogItem


class PredictionRecord(BaseModel):
    """A cached projection tied to its input files and generation preferences."""

    model_config = ConfigDict(extra="forbid")
    source_sha256: str
    dependency_fingerprint: str
    input_fingerprint: str
    completed_at: float
    result: ResourcePrediction


def prediction_destination(settings: StudioSettings) -> Path:
    """Use the same output parent as automatically constructed Studio runs."""
    return (
        settings.output_parents.get(str(settings.workspace.resolve()), settings.workspace / "runs")
        .expanduser()
        .resolve()
    )


def prediction_key(item: CatalogItem, dependencies: str, settings: StudioSettings) -> str:
    """Invalidate after content, tool, output-parent, or checkpoint changes."""
    command = _eforge_command(controller_settings(settings))
    tool = Path(command[0])
    try:
        tool_modified = tool.stat().st_mtime_ns
    except OSError:
        tool_modified = 0
    config_root = Path(__file__).resolve().parents[1] / "config"
    calibration_identity = [
        hashlib.sha256((config_root / name).read_bytes()).hexdigest()
        for name in ("generation_behavior.yaml", "resource_forecast.yaml")
    ]
    return hashlib.sha256(
        json.dumps(
            [
                __version__,
                item.source_sha256,
                dependencies,
                str(prediction_destination(settings)),
                settings.checkpoint_hours,
                command,
                tool_modified,
                calibration_identity,
            ]
        ).encode()
    ).hexdigest()


def run_prediction(
    item: CatalogItem, dependencies: str, settings: StudioSettings
) -> PredictionRecord:
    """Capture typed output; failure stays inspectable and cannot launch generation."""
    destination = prediction_destination(settings)
    try:
        completed = subprocess.run(
            [
                *_eforge_command(controller_settings(settings)),
                "resources",
                "predict",
                str(item.path),
                "--project-root",
                str(item.workspace),
                "--destination",
                str(destination),
                "--checkpoint-hours",
                str(settings.checkpoint_hours),
                "--json",
            ],
            cwd=item.workspace,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        result = ResourcePrediction.model_validate_json(completed.stdout)
        if completed.returncode and result.available:
            raise ValueError("eforge exited unsuccessfully while reporting an available prediction")
    except ValidationError:
        result = ResourcePrediction(
            destination=destination,
            checkpoint_hours=settings.checkpoint_hours,
            error="eforge returned an unsupported prediction report. Check its version and tool path.",
        )
    except subprocess.TimeoutExpired:
        result = ResourcePrediction(
            destination=destination,
            checkpoint_hours=settings.checkpoint_hours,
            error="Resource prediction took longer than 60 seconds. Refresh to retry.",
        )
    except (OSError, ValueError) as exc:
        result = ResourcePrediction(
            destination=destination,
            checkpoint_hours=settings.checkpoint_hours,
            error=f"Resource prediction could not finish: {exc}",
        )
    return PredictionRecord(
        source_sha256=item.source_sha256,
        dependency_fingerprint=dependencies,
        input_fingerprint=prediction_key(item, dependencies, settings),
        completed_at=time.time(),
        result=result,
    )
