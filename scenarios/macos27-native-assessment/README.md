# macOS 27 native coverage benchmark

This independent Schema 3 draft continues the invented Northstar Software consultancy environment.
It uses no packs, workstation inventory or captured native records. The original macOS 26
assessment sources remain historical inputs; this draft is the current macOS 27 arm64 benchmark.

Four hosts, three users, a six-hour window and one-hour warmup cover mixed Windows/Linux/Mac
activity, local GUI login/workspace entry, Mac SSH command chains, a plain nested shell, known
query completion, SMB client access, system launch-item stages, pre-child denial, returning exec
failure and explicit app-policy refusal. All commands are rendered synthetic intent, never run.

Validate and generate from the repository root:

```sh
uv run eforge validate scenarios/macos27-native-assessment/source/scenario.yaml
uv run eforge generate scenarios/macos27-native-assessment/source/scenario.yaml --output <fresh-bundle-root> --checkpoint-hours 0
uv run eforge eval <fresh-bundle-root> --format json
```

The target is `default`, with authored seed 327. Validation has no errors, one expected warning
because no firewall is collected, and four informational notices about independent users' adjacent
storyline steps. The source intentionally preserves those distinct users and activities.

Read `GROUND_TRUTH.json.macos_native_coverage` to distinguish exact native phases from authored
aggregate launches and metadata gaps. Native ES admits only the qualified v11 subset. GUI app
responsibility, full helper/PTY descriptors, native file/auth callbacks, populated entitlements,
full hashes and comprehensive Gatekeeper or Unified Log families remain unqualified. A passing
synthetic benchmark does not establish those missing native reference contracts.

Generated bundles stay ignored under `output/`. Only authored sources, reports and derived
assessment summaries belong in Git; captured records and raw log datasets never do.

The [first current-profile panel](blind-test/loop-1/REPORT.md) is followed by
[deterministic verification of the selected fixes](blind-test/verification-rev344/REPORT.md).
All five nested commands execute and the qualified native exec/exit pairs pass. This closes
the bounded development slice, with no new blind score. Further assessment loops require a
separate request; GUI app launch responsibility remains a reference-data dependency.
