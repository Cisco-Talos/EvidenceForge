# Studio validation feedback

During alpha-5 Studio acceptance, the user reported that clicking Validate did
not visibly confirm another check when the findings stayed identical. The user
requested clear running/completed feedback and an explicit request-failure message.

Scenario validation shows a spinner, hides earlier findings for the duration of
the request, and disables repeat validation while busy. The outcome identifies
errors, warnings or a passing result. Check timestamps include seconds. Activity
is scoped to the scenario and workspace and survives navigation within Studio.

Connection failures and CLI failures without a report retain the actual error
inline. Earlier findings are restored under Previous validation
results, including when a failed CLI check replaces the backend's saved report.
Retry immediately hides the old error and findings. Scenario finding errors are
completed checks, not request failures. Saved source/provenance and validation
rules are unchanged; no data migration or engine behavior change is needed.

Three App regressions cover repeated identical results, connection failure,
CLI timeout, retained prior findings and retry cleanup. All 351 frontend tests
pass across 34 files. TypeScript/Vite production build passes with the existing
large-chunk advisory. Repository Ruff lint/format and whitespace checks pass.
The Studio guide describes the states. The user accepted the interaction, then
requested removing the extra status badge: the spinner and hidden findings provide
sufficient feedback. Validation badges are removed; spinner, timestamps, inline
errors and prior-result recovery remain. Existing regressions check these behaviors
without requiring badges. Restart the source-launched app to load the changes if
hot reload is unavailable.

The separate chat/GUI engine mismatch repair is tracked in
[its worklog](2026-11-09-studio-chat-engine-selection.md).
