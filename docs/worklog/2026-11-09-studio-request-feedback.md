# Studio request feedback expansion

The user accepted spinner-based validation feedback without running/completed
badges and authorized applying the pattern to pack validation, Environment,
library refresh, resource forecasts, import review/prepared validation, and logs.
Import readiness labels describe the review outcome, not request lifecycle.

Implemented shared spinner, second-resolution timestamps and inline request errors
through `RequestFeedback`. Pack checks hide prior findings while pending. Their
existing authoritative follow-up review remains intact on a failed validation
action. Environment combines dependency-refresh and inspection progress, retains
an active header spinner through the inspection request, and reports errors inline
even with its details collapsed. These feedback records are workspace/item/source
scoped so an old revision's failure does not override a newly edited source.

Library refresh disables repeat requests, preserves visible contents, briefly
confirms completion and retains failure messages inline. Forecasts and log previews
remain visible and explicitly labeled while refreshing or after failure. New job
identity clears an unrelated prior log; changed forecast input identities invalidate
retained estimates and ignore late request feedback. Log refresh does not introduce
another run-status badge or present previous diagnostics as a fresh process failure.

Import checks use operation-specific spinners and timestamps. Optional validation
keeps findings advisory, hides them while pending and restores previous findings
with a request-failure message. Review refresh invalidates the old service review;
failed refreshes can show that review only as read-only previous information, with
no confirmation action. Readiness reflects selected dependencies and advisory
validation findings. Input changes clear review feedback; document choices are
disabled while requests run.

Focused tests cover identical pack checks, library completion/failure, full
Environment refresh ownership, retained forecast/log content and retry, import
readiness, failed-review confirmation exclusion and validation failure recovery.
The pre-existing changes from earlier Studio acceptance work remain in place.
No engine semantics, API schema, product version, publication, or generated data
was changed by this feedback expansion.

Validation: all 359 frontend tests pass across 35 files, including eight new
request-feedback regressions. TypeScript/Vite production build passes with the
existing large-chunk advisory. Whole-repository Ruff lint/format and whitespace
checks pass. Native interactive acceptance remains with the user; restart the
source-launched app if hot reload is unavailable.

## Environment reopening and header feedback

The user reported a fresh inspection on every Environment expansion. Workspace
sections unmounted their children when collapsed, discarding the view and
cancelling pending response adoption. Environment now opts into retaining its
contents after the first expansion. It remains lazy before that first opening;
collapsing does not cancel or duplicate a pending request. Reopening reuses the
inspection, while source/dependency/configuration changes and explicit refresh
continue to invalidate it. Retention is limited to the current scenario workspace;
other sections keep their existing mounting behavior.

The user also requested removing the separate Checked status line below the
section. Refresh progress and the check time now appear in the header summary,
alongside its existing spinner; only actual request errors use the inline footer.
The integrated regression covers first-load laziness, collapse during a pending
request, reuse of completed data/time, input invalidation and explicit refresh.
All 360 frontend tests pass across 35 files after this follow-up. The production
build and whitespace checks pass; the existing large-chunk advisory remains.

On November 9 the user reported Studio testing is fine after these changes.
Interactive acceptance of the source-launched app is recorded in the
[alpha-5 release handoff](2026-11-07-alpha5-readiness.md#latest-handoff--november-9).
