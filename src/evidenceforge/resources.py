# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only prediction contract shared by the CLI and local application service."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition import compile_scenario
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.resource_forecast import ResourceForecast, build_resource_forecast
from evidenceforge.generation.workload import estimate_workload
from evidenceforge.models.exceptions import EvidenceForgeError


class ResourcePrediction(BaseModel):
    """Informational projection; availability does not certify scenario validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = "1.0"
    available: bool = False
    error: str = ""
    scenario_name: str = ""
    source_sha256: str = ""
    destination: Path
    checkpoint_hours: int = Field(default=24, ge=0)
    forecast: ResourceForecast | None = None


def predict_resources(
    source: Path, destination: Path, *, project_root: Path | None = None, checkpoint_hours: int = 24
) -> ResourcePrediction:
    """Compile and estimate inputs without generating logs or creating output directories."""
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    prediction = ResourcePrediction(destination=destination, checkpoint_hours=checkpoint_hours)
    try:
        if source.stat().st_size > 8 * 1024**2:
            raise ValueError("Choose a scenario YAML file smaller than 8 MiB")
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        compiled = compile_scenario(source, project_root=project_root)
        with effective_config_scope(compiled.effective_config):
            estimate = estimate_workload(compiled.scenario, scenario_root=source.parent)
            forecast = build_resource_forecast(
                compiled.scenario, estimate, destination, checkpoint_hours=checkpoint_hours
            )
    except (EvidenceForgeError, OSError, ValueError, yaml.YAMLError) as exc:
        return prediction.model_copy(update={"error": str(exc)})
    return prediction.model_copy(
        update={
            "available": True,
            "scenario_name": compiled.scenario.name,
            "source_sha256": source_sha256,
            "forecast": forecast,
        }
    )
