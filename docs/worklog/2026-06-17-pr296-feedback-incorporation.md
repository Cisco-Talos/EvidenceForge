# PR #296 Feedback Incorporation + Rebase

Date: 2026-06-17
PR: `#296` (`feat: add adversarial_payload event type for log-pipeline weakness testing`)
Branch: `feature/adversarial-payload-v1`

## Context

PR #296 was rebased onto current `origin/dev` (`a89cef91` → `fe4bc439`, clean) and the
maintainer's 7-item pre-merge review was incorporated. Pre-rebase tip backed up at
`backup/adversarial-payload-v1-prerebase-20260617`. No push yet — pending owner approval.

Sibling branch `fix/process-read-event-keyerror` (PR #297) is dead: closed as superseded
by dev `7e3a3a52` (which already maps `read → file_read`); dev carried the regression test
forward in `4cf50430`. Safe to delete.

## Rebase regression (found + fixed)

After the rebase, `test_http_payload_visible_on_the_wire_when_plaintext` failed: dev
`7b8aabca` (Splunk output-target work) removed the Zeek "no sensor → flat http.json"
fallback, so a `zeek_*` format now emits only when a network sensor monitors the segment.
The wire test declared no `environment.network`, so `zeek_http.json` was never produced
(payload still in web_access.log / GROUND_TRUTH). Confirmed it passed pre-rebase. Fix is
test-only: gave the wire test a `placement: span` sensor on the shared 192.168.20.0/24
segment (mirrors `_ids_scenario` and dev's own realignment in `2094f3f5`), plus an
assertion that http.log lands under the sensor subdir.

## Commits on this branch (after rebase)

1. `test: realign on-the-wire zeek test with sensor routing` — the regression fix above.
2. `refactor: drop the proposed adversarial_payload family mechanism` — review items 1 + 7.
   Removed the `proposed` schema field, the 4 `proposed: true` YAML entries + "PROPOSED"
   wording, the validation warning, the proposed test; reworded docs so all 8 families read
   as supported and GROUND_TRUTH wording no longer implies secret redaction.
3. `feat: require a registrable domain or IP for --oob-host; drop --i-am-authorized` —
   items 2 + 3. New registrable-domain gate reuses in-repo `multi_label_public_suffixes()`
   (no new dependency, per the issue #284 "no external deps" constraint); rejects bare TLDs
   / single labels / public suffixes. `--i-am-authorized` removed; `--oob-host` alone is the
   opt-in (LIVE CALLBACK banner kept). Logic extracted to shared `_normalize_oob_hosts()`.
4. `feat: add eforge validate --oob-host parity with generate` — item 4. `validate` now takes
   `--oob-host` (no auth flag, matching the maintainer's example) via the shared helper.
5. `docs: tighten OOB/live-callback guidance ...` — items 5 + 6 (and this worklog). Skills +
   reference docs: agents never use `--oob-host` unless asked, OOB is generation-time-only
   (not YAML), text-only / no callbacks, inert canary by default; documented `validate
   --oob-host`.

## Verification

`uv run pytest tests/unit/test_adversarial_payload.py
tests/integration/test_adversarial_payload_generation.py --no-cov` green; `ruff check` /
`ruff format --check` clean; `eforge validate-config` clean. Final full non-slow suite run
recorded below.

## Next steps

- Push / force-push to update PR #296 only after the owner approves (pushes are gated).
- No version bump on this feature branch — the bump happens once on `dev` before the
  `dev → main` PR (AGENTS.md). Per SemVer this PR is a `feat:` (MINOR) when it lands.
- Optionally delete the dead `fix/process-read-event-keyerror` branch.
