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

## Deep-review (max-effort) findings + fixes

A second, empirical red-team (run generation, inspect on-disk bytes; do not trust a
code-reading audit) found two latent correctness issues in the original feature that the
first "all-fulfilled" audit missed, plus minor doc/test gaps. (Commits are referenced by
description, not SHA — SHAs change on rebuild.)

- **D1 — phantom-positive (FIXED):** the Linux-only-surface validator gate used
  `os_cat == "windows"`; a non-Linux/non-Windows actor (macOS/BSD/Solaris → "unknown") +
  syslog_message validated clean but never emitted, leaving a poisoned ground-truth label.
  Fixed to `!= "linux"`; `generate` aborts on the error (blocked end-to-end). This PR's D1
  fix is **adversarial_payload-only**. The identical spillage-validator fix was **moved to a
  standalone branch** (`fix/spillage-linux-only-os-gate`, off `dev`) and is NOT part of this
  PR — it fixes already-released code (PR #289) and ships independently, keeping this PR
  scope-clean.
- **D2 — IDS over-detection (RESOLVED: docs-only):** `ids_signature_for_payload` matched the
  decoded token regardless of surface, so crlf_log_forging fired a "CRLF in HTTP Header"
  alert (2012887) for a URL-borne, percent-encoded payload a raw-content rule could not match.
  **Decision: keep the maintainer-accepted firing model unchanged and fix it in docs only.**
  The surface-aware code change was reverted; behavior is back to: a signature fires when the
  (normalized) payload still carries its token, modeling a URI/UA-normalizing sensor, with
  obfuscations evading. The docs now carry an explicit sensor-model caveat: the on-wire form
  is percent-encoded, the SID/message are the upstream ET rule's own (so `2012887` may read
  "in HTTP Header" even for a URL payload), a raw-content sensor may not fire, and the
  ground-truth `surface` field is recorded so either interpretation is recoverable. GT↔disk
  was always consistent, so this was an interpretation issue, not a pipeline defect. A
  surface-gated / per-signature-applicability firing model remains a possible future
  enhancement (maintainer's call).
- **D3 — docs (FIXED):** rendered_value/rendered_sha256 is a carrier-wrapped substring for
  http_request_url/http_referrer (not just process_command_line) — documented.
- **D4 — tests (ADDED):** full (family×surface) matrix lands-on-disk (all 8 families), the
  emitted:false skip/no-leak invariant, and non-Linux OS-gate regressions (both validators).
  Timing checked: the matrix test runs ~3s, in line with existing un-gated integration tests
  (suite max ~5s), so it is intentionally NOT `@pytest.mark.slow`.

**Item 2 (--oob-host) — substantially addressed.** Every case the maintainer enumerated is
covered (reject com/fun/local/co.uk; accept concrete domains/subdomains/IPs; suffix scoped
to the registered domain). The curated `multi_label_public_suffixes` list was then EXPANDED
(12 → ~38) to cover common ICANN ccTLD second-levels (co.in, co.za, co.kr, com.cn, com.tr,
…) and common vendor "private" public suffixes (github.io, gitlab.io, herokuapp.com,
ngrok.io, s3.amazonaws.com, web.app, pages.dev, vercel.app, netlify.app, azurewebsites.net,
…), with a documented rationale block in `tls_realism.yaml`. So a bare vendor/registry
suffix is now rejected while a name *under* it (`abc.github.io`) stays registrable. It
remains a **curated common subset, not the full PSL** — deliberately, to honor the #284
"no external dependency / no vendored corpus" constraint — and is overlay-extensible.
Residual: a suffix outside the curated set is still accepted, but only behind the explicit
`--oob-host` opt-in + LIVE CALLBACK warning (operator footgun, not an attacker bypass), and
the bare-TLD case (`com`→`*.com`) is always closed by single-label rejection.

**Design note (for review): the safety gate shares the TLS/DNS public-suffix list.**
`--oob-host` reuses `multi_label_public_suffixes()` (also used by TLS SAN + DNS realism).
Pro: single source of truth, DRY, the additions are objectively correct public suffixes and
verified not to change TLS/DNS output for existing data (449 TLS/DNS/cert/OOB tests green).
Con: a safety boundary now depends on a list whose other purpose is cosmetic realism — a
future cosmetic edit could weaken the gate. Alternative if the maintainer prefers: decouple
into a dedicated `--oob-host` public-suffix denylist. Left shared for now (DRY + the user's
"expand the list" instruction); decoupling is a cheap follow-up.

Empirically confirmed solid (no defect): eval independently re-verifies payloads on disk;
overlay families are re-checked at generation; the raw/escaped control-byte matrix holds
per format; the host allowlist rejects every obfuscated public host (unicode/punycode/IP);
byte-identical determinism across runs. Full non-slow suite green (4381 passed, 41 skipped).

## Status — SUBMITTED (2026-06-17)

Both branches are pushed to the fork and have open PRs against `Cisco-Talos:dev`, awaiting
maintainer review:

- **PR #296** (`feature/adversarial-payload-v1`, head `496a7c61`, 14 commits) — updated via
  force-push (history was rebased onto current `dev`), with a detailed comment mapping each of
  the maintainer's 7 review items to its change plus the deep-review findings/decisions.
- **PR #323** (`fix/spillage-linux-only-os-gate`, off `dev`) — the spillage phantom-positive
  twin, split out so it can ship independently of the feature.

Pre-submission gates: full non-slow suite green (4,378 passed, 41 skipped); `ruff` clean;
`eforge validate-config` clean; an independent maintainer-style review returned APPROVE (its
one nit — per-label `--oob-host` hostname validation — is fixed). Local branches now track the
fork; the session backup branches were pruned.

Decisions on record: **D2 = docs-only** (IDS firing model unchanged; sensor-model caveat
documented; surface-gating offered to the maintainer); **spillage = standalone PR**;
**`--oob-host` public-suffix list = kept shared** with TLS/DNS realism (expanded ~12→38,
documented; decouple-into-a-dedicated-list remains an offered follow-up).

## Round 2 — maintainer (DavidJBianco) re-test, 2 required fixes (FIXED)

David re-tested against head `496a7c61` and found two issues our review missed. Both fixed:

1. **OOB safety enforced at the wrong layer (FIXED).** The CLI rejected broad `--oob-host`
   values (`com`), but `check_payload_safety()` / `resolve_value()` trusted whatever `oob_hosts`
   they were handed — so a *broad value reaching the safety path directly* still allowlisted a
   whole namespace (`evil.com` suffix-matches `.com`). Moved the contract into a single
   `adversarial_payload.normalize_oob_host()` enforced AT the safety boundary (the CLI now calls
   the same helper for fail-fast UX). Regression test: broad values passed straight to
   `check_payload_safety`/`resolve_value` now raise.
2. **`expected_sources` overclaimed (FIXED).** `zeek_http` was appended for any cleartext-http
   payload (theoretical wire visibility), even when zeek wasn't configured or no sensor observed
   it — so GROUND_TRUTH named a source with no file. Now gated on the `zeek_http` emitter being
   configured AND a sensor on the path actually observing Zeek; `expected_sources` means "exists
   in this dataset." Tests: excluded when not observed, included when observed, plus an
   inverse-completeness test asserting every claimed source produced a file.

### Lessons learned (why our extensive review missed these)

- **Test the invariant at its owning boundary, not just the caller.** We verified the CLI gate
  and that `check_payload_safety` rejects bad *payload hosts*, but never called the safety core
  with a *broad `oob_hosts`*. We fixed the symptom where the value enters (CLI) instead of where
  the invariant lives (the allowlist construction). Fix root causes at the owning layer (AGENTS.md).
- **Assert completeness, not just presence.** Our "lands on disk" / eval checks asserted the
  payload appears in *at least one* expected source — never that *every* claimed source exists.
  A phantom *source* (vs. the phantom *record* we did catch) was structurally invisible. New
  invariant test: `set(expected_sources)` ⊆ sources actually produced.
- **Don't prime an "independent" reviewer with our conclusions.** The independent pass was seeded
  with our framing ("registrable detection reuses the list; bare suffix rejected"), so it verified
  that premise *at the CLI* rather than re-deriving the invariant. Give a reviewer the raw
  invariants to attack.
- **Author bias:** we tested "does my code do what I intended"; the owner tested "does the system
  uphold the property, including where my code doesn't reach." Both new tests encode the property.

These three checks (boundary-direct hostile-input tests; expected-vs-produced completeness; raw
invariants for reviewers) are now part of the audit checklist below.

## Open / next

- Awaiting maintainer review on PR #296 and PR #323; CI runs on both.
- One open question put to the maintainer: whether to surface-gate the IDS alert (a
  header-named signature not firing for a URL-borne payload) — an easy follow-up either way.
- No version bump on the feature branch — the bump happens once on `dev` before the
  `dev → main` PR (AGENTS.md). This PR is a `feat:` (MINOR) when it lands.
- The 4 pre-existing `feature/adversarial-payload-v1-prerebase{,2,3,4}` fork branches remain
  (not from this effort); optionally delete them and the dead `fix/process-read-event-keyerror`.
- GitHub wiki note: the upstream wiki is enabled but uninitialized and we have pull-only
  access, so this worklog + the two PRs are the status surface — a wiki Home page would need a
  maintainer with push access.
