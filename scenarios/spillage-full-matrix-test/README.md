# Spillage Full Matrix Test

This scenario is a committed compatibility fixture for the data-driven
`spillage` event type. It is intentionally a compact matrix harness rather than
a realistic threat-hunting story.

Use it when changing spillage family definitions, surface rendering,
scheme-aware HTTP/HTTPS selection, source visibility, or ground-truth labeling.
The fixture covers every built-in secret family, every semantic spillage
surface, Linux and Windows process command-line paths, HTTP-only and HTTPS-only
web targets, omitted-scheme auto-selection, and proxy-bypass behavior.

Quick validation:

```bash
uv run eforge validate scenarios/spillage-full-matrix-test/scenario.yaml
uv run eforge generate scenarios/spillage-full-matrix-test/scenario.yaml --output /private/tmp/eforge-spillage-full-matrix --force
uv run eforge eval /private/tmp/eforge-spillage-full-matrix/data --scenario scenarios/spillage-full-matrix-test/scenario.yaml
```

The authored scenario notes live in `ENVIRONMENT.md`. Generated output should
not be committed.
