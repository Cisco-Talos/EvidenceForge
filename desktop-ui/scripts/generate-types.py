"""Generate Studio's TypeScript API schema from the Python service models."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from evidenceforge.naming import NAMING_RULES
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import create_app


def main() -> None:
    """Write generated API declarations without using real app data."""
    check = sys.argv[1:] == ["--check"]
    if sys.argv[1:] and not check:
        raise SystemExit("Usage: generate-types.py [--check]")
    ui_directory = Path(__file__).resolve().parents[1]
    target = ui_directory / "src" / "generated" / "studio.ts"
    naming_target = target.with_name("naming.ts")
    naming = (
        "// Generated from evidenceforge.naming; do not edit.\nexport const namingRules = "
        + json.dumps({kind: rule.model_dump() for kind, rule in NAMING_RULES.items()}, indent=2)
        + " as const;\n"
    )
    if check:
        if not naming_target.is_file() or naming_target.read_text() != naming:
            raise SystemExit("Studio naming rules are stale; run npm run types:generate")
    else:
        naming_target.write_text(naming)
    with tempfile.TemporaryDirectory(prefix="eforge-studio-schema-") as temporary:
        root = Path(temporary)
        os.environ["EFORGE_STUDIO_DEFAULT_WORKSPACE"] = str(root / "workspace")
        paths = StudioPaths(
            config=root / "config",
            data=root / "data",
            state=root / "state",
            cache=root / "cache",
            logs=root / "logs",
        )
        app = create_app(paths, "schema-only-token", schema_only=True)
        schema = root / "openapi.json"
        schema.write_text(json.dumps(app.openapi()), encoding="utf-8")
        output = root / "studio.ts" if check else target
        subprocess.run(
            [
                str(ui_directory / "node_modules" / ".bin" / "openapi-typescript"),
                str(schema),
                "-o",
                str(output),
            ],
            check=True,
            cwd=ui_directory,
        )
        if check and (not target.is_file() or output.read_bytes() != target.read_bytes()):
            raise SystemExit("Studio API types are stale; run npm run types:generate")


if __name__ == "__main__":
    main()
