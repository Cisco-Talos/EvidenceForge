# How to Contribute

Thanks for your interest in contributing to EvidenceForge! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-foundation-ai/EvidenceForge/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Suggesting Features

Feature requests are welcome! Open a GitHub Issue with the **enhancement** label
and include:

- A clear description of the feature and the problem it solves
- Example usage or scenario where the feature would be helpful
- Any relevant references (e.g., log format specs, MITRE ATT&CK techniques)

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

Before submitting, run the full test suite (including slow tests) and confirm
all tests pass:

```bash
uv run pytest --include-slow
```

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Prefix
your commit message with a type:

- `feat:` — new feature or capability
- `fix:` — bug fix
- `docs:` — documentation changes
- `test:` — adding or updating tests
- `refactor:` — code changes that neither fix a bug nor add a feature
- `chore:` — maintenance tasks (dependencies, CI, tooling)

Examples:
```
feat: add SMTP log emitter
fix: correct Zeek UID correlation for DNS queries
docs: update scenario reference with dhcp_lease event type
test: add integration tests for proxy emitter
```

### Pull Request Descriptions

Describe what changed and why. Reference any related issues (e.g.,
`Closes #42`). If the change affects log output or scenario schema, include
a brief example of the before/after behavior.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/cisco-foundation-ai/EvidenceForge.git
cd EvidenceForge

# Install dependencies (requires uv: https://docs.astral.sh/uv/)
uv sync

# Run the test suite (1100+ tests, skips slow by default)
uv run pytest

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

### Test Markers

- `@pytest.mark.slow`: large dataset tests (100+ users), skipped by default

```bash
uv run pytest                  # Quick run (skips slow tests)
uv run pytest --include-slow   # Full run (all tests, required before PRs)
uv run pytest -m slow          # Only slow tests
```

## Code Style

EvidenceForge follows strict coding conventions documented in [AGENTS.md](/AGENTS.md). Key points:

- **Type hints everywhere** — all functions, methods, and variables
- **Pydantic v2** for all structured data
- **100 character** line length, **4 space** indentation, **double quotes**
- **Google-style docstrings** for public functions
- **`uv`** for all dependency management (never `pip`)
- **`pathlib.Path`** for all path handling (never string paths)

Linting is enforced via `ruff` with pycodestyle, pyflakes, isort, pep8-naming, pyupgrade, and flake8-bugbear rules.

## Adding a New Log Format

1. Create a format definition YAML in `src/evidenceforge/formats/definitions/`
2. Create an emitter class in `src/evidenceforge/generation/emitters/` inheriting from `LogEmitter`
3. Register the emitter in `src/evidenceforge/generation/emitters/__init__.py`
4. Add emitter initialization in the engine (`src/evidenceforge/generation/engine/emitter_setup.py`)
5. Create a parser in `src/evidenceforge/evaluation/parsers/` for eval support
6. Add tests for the emitter and parser
7. Document the format in `docs/reference/EVIDENCE_FORMATS.md`

## Adding a New Event Type

1. Add the event spec Pydantic model to `src/evidenceforge/models/scenario.py`
2. Add a handler in `ActivityGenerator` (`src/evidenceforge/generation/activity/generator.py`)
3. Add any needed context fields to `src/evidenceforge/events/contexts.py`
4. Implement `_render_{event_type}()` on relevant emitters
5. Update `src/evidenceforge/validation/schema.py` for cross-reference validation
6. Update `docs/reference/scenario-reference.md`
7. Add tests

## Other Ways to Contribute

We welcome anyone that wants to contribute to EvidenceForge to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review existing pull requests, and testing patches against EvidenceForge.
- Write a test, or add a missing test case to an existing test.
- Create new example scenarios for different attack types.
- Improve documentation or add tutorials.

Thanks again for your interest in contributing to EvidenceForge!
