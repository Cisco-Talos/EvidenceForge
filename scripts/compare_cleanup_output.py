"""Capture and compare raw deterministic evidence across isolated source checkouts.

Run with the same locked Python environment for both checkouts. Output directories
must be new; captures never replace a baseline. The generation manifest is compared
structurally except for its creation time. All evidence files are compared,
including ground truth and source-observation sidecars.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def snapshot(root: Path) -> dict[str, str]:
    """Hash every evidence file without normalizing its bytes or relative name."""
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.relative_to(root).as_posix() == "generation.log":
            continue
        if path.relative_to(root).as_posix() == "GENERATION_MANIFEST.json":
            manifest = json.loads(path.read_text(encoding="utf-8"))
            for relative, expected in manifest["files"].items():
                with (root / relative).open("rb") as stream:
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
                if actual != expected:
                    raise ValueError(f"Manifest hash mismatch: {relative}")
            del manifest["created_at"]
            hashes["GENERATION_MANIFEST.json"] = hashlib.sha256(
                json.dumps(manifest, sort_keys=True).encode("utf-8")
            ).hexdigest()
            continue
        with path.open("rb") as stream:
            hashes[path.relative_to(root).as_posix()] = hashlib.file_digest(
                stream, "sha256"
            ).hexdigest()
    return hashes


def capture(arguments: argparse.Namespace) -> None:
    """Generate against the selected source tree in this fresh process."""
    sys.path.insert(0, str(arguments.source.resolve() / "src"))
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_yaml

    original_init = LogEmitter.__init__
    if arguments.serial:

        def initialize_serial(self: LogEmitter, *args: Any, **kwargs: Any) -> None:
            if len(args) >= 4:
                args = (*args[:3], False, *args[4:])
            else:
                kwargs["threaded"] = False
            original_init(self, *args, **kwargs)

        LogEmitter.__init__ = initialize_serial

    document = load_yaml(arguments.fixture.resolve())
    scenario = Scenario(**document)
    if arguments.filtered:
        scenario.output.logs = [{"format": "zeek"}]
    arguments.output.mkdir(parents=True, exist_ok=False)
    GenerationEngine(
        scenario,
        arguments.output,
        generation_seed=arguments.seed,
        output_target=arguments.target,
    ).generate()
    hashes = snapshot(arguments.output)
    arguments.output.with_suffix(".hashes.json").write_text(
        json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Captured {len(hashes)} evidence files in {arguments.output}")


def main() -> None:
    """Capture a new bundle or compare two existing bundles exactly."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("capture")
    generate.add_argument("--source", type=Path, required=True)
    generate.add_argument("--fixture", type=Path, required=True)
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--target", choices=("default", "sof-elk", "splunk"), default="default")
    generate.add_argument("--serial", action="store_true")
    generate.add_argument("--filtered", action="store_true")
    compare = commands.add_parser("compare")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "capture":
        capture(arguments)
        return
    baseline, candidate = snapshot(arguments.baseline), snapshot(arguments.candidate)
    differences = [
        name
        for name in sorted(baseline.keys() | candidate.keys())
        if baseline.get(name) != candidate.get(name)
    ]
    if differences:
        raise SystemExit("Evidence differs: " + ", ".join(differences))
    if not baseline:
        raise SystemExit("Cannot accept empty evidence")
    print(f"PASS: {len(baseline)} matching artifacts; raw evidence bytes are identical")


if __name__ == "__main__":
    main()
