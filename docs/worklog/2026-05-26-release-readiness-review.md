# Release Readiness Review

## Status

Active release-readiness handoff for the GitHub/source release planned after
work on `dev` is ready to PR into `main`.

The review started as read-only recommendations. User-approved fixes may be
implemented one item at a time, but future agents should continue asking for
approval before making fixes that were only reviewed/recommended.

## Scope

Review areas agreed with the user:

- Documentation and onboarding, especially first-user clarity and the path from
  clone to creating evidence.
- Release metadata: version consistency, changelog readiness, repo links,
  license/security/contribution docs, and release-note treatment for known gaps.
- CI and test posture: configured workflows and recommended release gate
  commands/status checks.
- CLI and package surface: documented commands, output layout, skill
  installation behavior, and source package expectations.
- Example and scenario hygiene: included examples, fixtures, and committed
  scenario artifacts suitable for a public source release.
- Security/legal hygiene: obvious secrets, sensitive artifacts, unsafe release
  collateral, dependency/lockfile drift, disclosure and license basics.
- Release operations: branch state, tag/release-note prep, post-merge smoke
  checks, and accepted-limitations wording.

Explicitly out of scope by user request:

- Data quality and realism assessment.
- Performance and scale assessment.
- Unapproved file edits, formatting, cleanup, commits, version bumps, changelog
  rewrites, artifact deletion, or workflow changes.

## Current Handoff

Next review item: security/legal hygiene.

## Decisions

- Release channel is GitHub/source, not PyPI.
- Current work happens on `dev`; final release PR will be `dev` to `main`.
- Version bump should happen as the final release-prep commit on `dev` before
  opening the `main` PR.
- Since `main` is already `1.0.0`, current expectation is a patch bump to
  `1.0.1` for the `dev` to `main` release PR unless later commits require a
  different bump under the repo rules.
- PR #264 (`fix: render ASA ICMP messages without interface prefixes`) is
  already merged into `dev`.
- Beginner public scenario should be named `branch-office-example`.
- Only the beginner scenario YAML should ship from that scenario bundle; no
  generated `data/`, ground truth, manifest, output-target marker, or companion
  environment docs should be tracked for it.
- The top-level `scenarios/COVERAGE-TEST-PROMPT.md` and
  `scenarios/LARGE-SCALE-COVERAGE-TEST-PROMPT.md` files are intentionally
  tracked and may remain in the public source release.
- Other prompt/review artifacts under `scenarios/`, including iteration-test
  blind-review loop outputs, should not be tracked for the public source
  release.
- Realistic public IP addresses and domains in public scenario/docs examples are
  intentional; do not replace them with obvious documentation-only ranges/names
  as part of this release-readiness cleanup.

## Completed Work

Committed in `fe5d4785 docs: add branch office example scenario`:

- Fixed README clone URL from the stale `cisco-foundation-ai` URL to
  `https://github.com/Cisco-Talos/EvidenceForge.git`.
- Updated README Quick Start to use
  `scenarios/branch-office-example/scenario.yaml`.
- Added `scenarios/branch-office-example/scenario.yaml`, a small branch-office
  scenario with Windows, Zeek, eCAR, syslog, bash history, Snort, Cisco ASA,
  web access, and proxy access outputs.
- Updated `.gitignore` so only
  `scenarios/branch-office-example/scenario.yaml` is unignored from that
  scenario bundle.

Current branch state after that commit: `dev` is ahead of `origin/dev` by one
commit.

Implemented after `72e210dc` during command-doc onboarding cleanup:

- Removed stale `--config` option from `commands/eforge/generate.md`.
- Corrected undefined-storyline-actor guidance so it matches validator rules:
  defined users, built-in accounts, or `environment.service_accounts`.
- Fixed the `generate.md` log-format table so `web_access` and `proxy_access`
  are normal rows.
- Added source-checkout guidance to use `uv run eforge ...` while installed
  package users can run `eforge` directly.
- Corrected `create_remote_thread` causal reference timing from `after` to
  `before`.
- Corrected the command-copy evidence-format output tree so eCAR, web access,
  proxy access, and Snort files are shown under their actual host/sensor
  directories.

Implemented during release metadata cleanup:

- Added package project URLs for Homepage, Repository, Issues, and Changelog.
- Updated stale `cisco-foundation-ai` repo links in `CONTRIBUTING.md` to
  `Cisco-Talos/EvidenceForge`.
- Corrected README evaluation-summary text from the superseded
  5-dimension/23-sub-score model to the active 4-pillar/20-sub-score model.
- Updated the Code of Conduct enforcement contact to Talos branding and
  `talos-external@cisco.com`.

Implemented during CI/test posture cleanup:

- Updated README and contributing setup commands to use `uv sync --all-extras`
  so local environments include pytest, Ruff, and other dev tools.
- Documented that slow tests should run with `--no-cov` and release coverage
  should run on the default non-slow suite.
- Clarified `AGENTS.md` coverage guidance: 70% is the enforced release gate,
  while 95%+ remains aspirational for overall and core generation coverage.
- Updated README's approximate pytest suite size from `1400+` to `3700+` after
  `uv run pytest --collect-only -q` collected `3775` tests.
- Added the Talos announcement blog link near the top of README.

Implemented during CLI/package surface cleanup:

- Added `-h` as an alias for `--help` on the root `eforge` command and all
  current subcommands through Typer `help_option_names`.
- Added focused CLI tests covering `-h` on root, `generate`, `validate`, `eval`,
  `install-skills`, `info`, `validate-config`, and `version`.
- Documented the `-h` alias in README's CLI reference.
- Aligned public evidence-format docs with the generated `data/` output tree.
- Updated `eforge eval` help text from "multiple dimensions" to "four pillars".
- Reworded README CLI flag guidance so generate-only flags are not described as
  common to all commands.

Implemented during example/scenario hygiene cleanup:

- De-tracked `scenarios/ITERATION-LOOP-FAMILY-IMPROVEMENT-PROMPT.md` and
  `scenarios/ITERATION-TEST-PROMPT.md`.
- De-tracked generated blind-review loop artifacts under
  `scenarios/iteration-test/blind-test/loop-132` through `loop-142`.
- Kept `scenarios/COVERAGE-TEST-PROMPT.md`,
  `scenarios/LARGE-SCALE-COVERAGE-TEST-PROMPT.md`, and
  `scenarios/branch-office-example/scenario.yaml` tracked.

Implemented during security/legal hygiene cleanup:

- Confirmed GitHub private vulnerability reporting is enabled for the public
  repository.
- Added MIT package license metadata and license-file inclusion to
  `pyproject.toml`.
- Added Dependabot coverage for GitHub Actions workflows, targeting `dev`.
- Switched package author metadata to `Cisco Talos` without a public email
  address.

## Validation

Validated before committing `fe5d4785`:

- `uv run eforge validate scenarios/branch-office-example/scenario.yaml`
  passed cleanly.
- `uv run eforge generate scenarios/branch-office-example/scenario.yaml -o /private/tmp/eforge-branch-office-example-smoke-codex --force`
  completed successfully.
- `uv run eforge eval /private/tmp/eforge-branch-office-example-smoke-codex/data --scenario scenarios/branch-office-example/scenario.yaml`
  passed with overall score `97/100`, `49,237` records across `18` sources, and
  acceptance `PASS`.
- Emitted smoke-test files included Cisco ASA, web access, proxy access, Snort,
  Zeek logs, Windows Security/Sysmon XML, eCAR JSON, syslog, and bash history.
- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.

Command-doc cleanup validation:

- `git diff --check` passed.
- Spot checks confirmed the stale generate `--config` option and obsolete
  literal `"attacker"` actor guidance are gone from command docs.

CI/test posture cleanup validation:

- `uv run pytest --collect-only -q` collected `3775` tests.
- `git diff --check` passed.
- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.

CLI/package surface cleanup validation:

- `uv run pytest tests/unit/test_cli.py::TestHelpAliases -q` passed.
- `uv run pytest tests/unit/test_cli.py -q` passed.
- `uv run eforge -h` and `uv run eforge generate -h` both showed `--help`
  and `-h` in help output.
- `uv run eforge --help` and `uv run eforge eval -h` showed updated
  four-pillar eval help text.
- `uv run pytest tests/unit/test_install_skills.py -q` passed.
- `git diff --check` passed.
- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.

Example/scenario hygiene validation:

- `git ls-files scenarios` now lists only
  `scenarios/COVERAGE-TEST-PROMPT.md`,
  `scenarios/LARGE-SCALE-COVERAGE-TEST-PROMPT.md`, and
  `scenarios/branch-office-example/scenario.yaml`.

Security/legal hygiene validation:

- Targeted secret scans did not find live-looking AWS, GitHub, Slack, bearer
  token, or private-key material in tracked files.
- Generated-output/artifact scan found only expected test fixtures under
  `tests/fixtures`.
- `uv lock --check` passed.

## Open Review Items

- Security/legal hygiene.
- Release operations checklist and accepted-limitations wording.

## References

- `TODO.md` remains the durable backlog and roadmap.
- `README.md` contains the updated Quick Start.
- `scenarios/branch-office-example/scenario.yaml` is the beginner scenario.
- Commit: `fe5d4785 docs: add branch office example scenario`.
