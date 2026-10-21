# macOS mixed-fleet assessment benchmark

This scenario-local software-company benchmark exercises two macOS 26 arm64
workstations, a Windows workstation and an Ubuntu SSH/Samba server. It is synthetic
authored input; no personal inventories or host logs were used.

`revisions/01-supported/` preserves the complete CLI-created Schema 3 draft layout,
including its UUID and `draft.json`, as a tracked benchmark snapshot. The original
managed draft remains under `.eforge/artifacts/drafts/scenario/macos-assessment/`.
Use the tracked `source/scenario.yaml` as the assessment input. Do not edit this
revision after the first successful baseline; create a separately identified revision for additional
native sources or materially different coverage. This is not a published scenario.

Revision 1 uses seed 327, a six-hour window and one-hour warmup. It selects eCAR,
Zeek, Windows, Linux syslog, Bash/zsh histories and the bounded macOS Unified Log
workspace-entry source. Endpoint Security is deliberately deferred to revision 2.

`revisions/02-native/` is a separate CLI-created draft, UUID
`9066de90-8a34-4cb9-a70c-645254ff53ed`. It keeps the same environment, activities,
seed and window and explicitly adds modeled fork/v10 ES output. Native exec/exit
and policy-denial export remain separately gated. This coverage change must not
be mistaken for a direct same-source score comparison with revision 1.
No firewall collector is modeled; its validation warning is intentional. Independent
users and maintenance activity need not form one attack chain, so adjacent-entry
pivot advisories are informational. Optional ATT&CK mappings are omitted.

Coverage includes local GUI sessions, local commands, an HTTPS manifest fetch,
Mac-to-Linux SSH, Windows-to-Mac SSH, a mounted Samba read, separate root system-job
write/bootstrap/activate/exit/unload/remove stages, and a terminal policy-rejected
execution attempt. Registration and denial currently have no native evidence;
their absence must not be mistaken for successful execution.

Fresh bundles live outside the repository. Only their `data/` contents are copied
to neutral reviewer directories. Reviewers never receive this file, scenario input,
the environment briefing, ground truth, quantitative evaluation or prior reports.
Assessment reports, scores, input hashes and run provenance belong in `blind-test/`.
See the assessment worklog for the current loop and implementation follow-through.

The retained `probe_evidence.py` checks visible process birth/dependent/close and
parent relationships, `/netonly` terminal placement, TLS histories versus matching
connection payloads, and selected native fork counts. Run it only on evidence
authorized for inspection. Equal millisecond timestamps are treated as unordered.
