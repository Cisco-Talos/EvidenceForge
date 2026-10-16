"""Read-only checks against the current EvidenceForge source checkout."""

import json
import subprocess
from datetime import UTC, datetime

from pydantic import ValidationError

from evidenceforge.events.content_identity import canonical_native_path
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, source_platform_for_os
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.deployment_compiler import (
    infer_system_platform,
    resolve_system_architecture,
)
from evidenceforge.generation.source_deployment_compiler import compile_scenario_source_deployment
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StorageVolumeConfig,
    System,
    TimeWindow,
    User,
)
from evidenceforge.validation.schema import _get_os_category as validation_os_category

rows: list[dict[str, object]] = []
for label in ("Windows 11", "Ubuntu 24.04", "macOS 15", "macOS 26", "Darwin", "OS X"):
    system = System(
        hostname="WS-01", ip="192.0.2.10", os=label, type="workstation", services=["ssh"]
    )
    scenario = Scenario(
        name="macos-feasibility-probe",
        description="In-memory capability probe",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="alice",
                    full_name="Alice Example",
                    email="alice@example.test",
                    persona="developer",
                    primary_system="WS-01",
                )
            ],
            systems=[system],
        ),
        time_window=TimeWindow(start=datetime(2026, 10, 15, tzinfo=UTC), duration="1h"),
        baseline_activity=BaselineActivity(description="Test", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "ecar"}], destination="/tmp/unused-macos-feasibility"),
    )
    world = WorldModel(scenario, "")
    deployment = compile_scenario_source_deployment(scenario)
    rows.append(
        {
            "os": label,
            "activity_platform": _get_os_category(label),
            "validation_platform": validation_os_category(label),
            "source_platform": source_platform_for_os(label),
            "deployment_platform": infer_system_platform(system),
            "default_architecture": resolve_system_architecture(system),
            "world_capabilities": sorted(world.hosts["WS-01"].capabilities),
            "ecar_applicable": DEFAULT_SOURCE_CATALOG.descriptor("ecar").applies_to_host(
                source_platform_for_os(label)
            ),
            "ecar_source_instances": list(deployment.source_instances),
        }
    )

apfs_error: str | None = None
try:
    StorageVolumeConfig(id="root", mount="/", filesystem="apfs")
except ValidationError as exc:
    apfs_error = exc.errors(include_url=False)[0]["msg"]

print(
    json.dumps(
        {
            "source_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "assessment_date": "2026-10-15",
            "scope": "In-memory model compilation, not generation or full scenario validation",
            "platform_probes": rows,
            "apfs_validation_error": apfs_error,
            "macos_case_variant_path_keys_equal": canonical_native_path(
                "/Users/Alice/Report.txt", "macos"
            )
            == canonical_native_path("/Users/Alice/report.txt", "macos"),
        },
        indent=2,
    )
)
