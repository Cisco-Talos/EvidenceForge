"""Independent checks for authored source-local raw escape hatches."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from evidenceforge.config.observation_profiles import get_observation_profile
from evidenceforge.events.ground_truth_occurrence import GroundTruthRawExpectation
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG
from evidenceforge.models import Scenario
from evidenceforge.models.scenario import RawEventSpec


def validate_raw_expectation(
    receipt: dict[str, Any], scenario: Scenario, spec: RawEventSpec, system: str
) -> tuple[bool, list[str]]:
    """Verify raw input ownership and its independent deterministic loss decision."""
    errors: list[str] = []
    try:
        contract = GroundTruthRawExpectation.model_validate(receipt)
        at = contract.time
        data = dict(receipt["fields"])
        for key in receipt["datetime_fields"]:
            data[key] = datetime.fromisoformat(data[key])
        if receipt["version"] != 1 or receipt["format"] != spec.target_format:
            errors.append("invalid_raw_contract")
        if any(data.get(key) != value for key, value in spec.fields.items()):
            errors.append("raw_authored_fields_disagreement")
        host = next(host for host in scenario.environment.systems if host.hostname == system)
        if "hostname" not in spec.fields and data.get("hostname") != host.hostname:
            errors.append("raw_host_disagreement")
        domain = scenario.environment.domain or next(
            (
                user.email.split("@", 1)[1]
                for user in scenario.environment.users
                if user.email and "@" in user.email and "." in user.email.split("@", 1)[1]
            ),
            "corp.local",
        )
        expected_data = dict(spec.fields)
        expected_data.setdefault("timestamp", at)
        expected_data.setdefault("hostname", host.hostname)
        expected_data.setdefault(
            "_host_fqdn", host.hostname if "." in host.hostname else f"{host.hostname}.{domain}"
        )
        if data != expected_data:
            errors.append("raw_input_envelope_disagreement")
        family = DEFAULT_SOURCE_CATALOG.descriptor(spec.target_format).family
        profile = get_observation_profile(scenario.observation_profile)
        settings = dict(profile.get("default", {}))
        settings.update(profile.get("sources", {}).get(family, {}))
        base = float(
            settings.get("format_missingness", {}).get(
                spec.target_format, settings.get("missingness", 0)
            )
        )
        multipliers = settings.get("host_missingness_multiplier", {})
        lower = max(0.0, min(float(multipliers.get("min", 1)), 10.0))
        upper = max(0.0, min(float(multipliers.get("max", 1)), 10.0))
        if upper < lower:
            lower = upper = 1.0

        def seed(key: str) -> int:
            if scenario.generation_seed != 42:
                key = f"seed:{scenario.generation_seed}:{key}"
            return int(hashlib.sha256(key.encode()).hexdigest(), 16) % 2**32

        multiplier = random.Random(
            seed(f"observation.host-mult|{scenario.observation_profile}|{family}|")
        ).uniform(lower, upper)
        probability = max(0.0, min(base * multiplier, 1.0))
        identity = "|".join(
            [
                family,
                spec.target_format,
                str(int(at.timestamp() * 1_000_000)),
                str(sorted(data.items()))[:500],
            ]
        )
        dropped = (
            random.Random(
                seed(f"observation.drop|{scenario.observation_profile}|{identity}")
            ).random()
            < probability
        )
        expected = not dropped
        if receipt["status"] != ("dropped" if dropped else "visible"):
            errors.append("invalid_raw_loss_explanation")
        return expected, errors
    except (KeyError, ValueError, TypeError, StopIteration, ValidationError):
        return True, ["invalid_raw_contract"]
