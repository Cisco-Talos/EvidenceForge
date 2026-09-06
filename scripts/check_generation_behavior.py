"""Validate the declared EvidenceForge generation-behavior surface digest."""

from __future__ import annotations

import argparse
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path

import yaml

from evidenceforge.generation.checkpoints.behavior import (
    generation_behavior_surface_digest,
    validate_generation_behavior_surface,
)


def _base_revision(reference: str) -> int | None:
    result = subprocess.run(
        ["git", "show", f"{reference}:src/evidenceforge/config/generation_behavior.yaml"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    document = yaml.safe_load(result.stdout)
    if type(document) is not dict or type(document.get("current_revision")) is not int:
        raise SystemExit("base generation behavior manifest is malformed")
    return document["current_revision"]


def _base_surface_digest(reference: str) -> str:
    archive = subprocess.run(
        ["git", "archive", "--format=tar", reference, "src/evidenceforge"],
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="eforge-behavior-base-") as temporary:
        root = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            bundle.extractall(root, filter="data")
        return generation_behavior_surface_digest(root / "src" / "evidenceforge")


def require_revision_for_surface_change(
    *,
    prior_revision: int,
    prior_digest: str,
    current_revision: int,
    current_digest: str,
) -> None:
    """Fail when a changed behavior surface reuses an existing revision."""

    if prior_digest != current_digest and current_revision <= prior_revision:
        raise SystemExit(
            "generation behavior changed without a new manifest revision: "
            f"base={prior_revision}, current={current_revision}"
        )


def main() -> None:
    """Fail when generation behavior changed without a manifest revision."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref")
    arguments = parser.parse_args()
    manifest = validate_generation_behavior_surface()
    if arguments.base_ref:
        prior_revision = _base_revision(arguments.base_ref)
        if prior_revision is not None:
            prior_digest = _base_surface_digest(arguments.base_ref)
            require_revision_for_surface_change(
                prior_revision=prior_revision,
                prior_digest=prior_digest,
                current_revision=manifest.current_revision,
                current_digest=manifest.behavior_surface_sha256,
            )
    print(
        "Generation behavior manifest is current: "
        f"revision={manifest.current_revision} digest={manifest.behavior_surface_sha256}"
    )


if __name__ == "__main__":
    main()
