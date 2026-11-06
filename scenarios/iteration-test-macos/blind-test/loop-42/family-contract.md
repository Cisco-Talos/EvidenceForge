# Shared baseline SMB arrivals

Classification: sibling_defect; family_level. Owner: baseline arrival planner and typed host-activity policy. Both mixed-fleet preplanning and Windows inline paths request scoped host/hour/seed Hawkes opportunities instead of a fixed host interval with2%jitter. Existing scaled interval policy owns mean rate; validated branching/decay plus a generous resource ceiling own burst shape. Counts vary, empty hours are possible, and the ceiling is not a quota. Content selection, mount admission, authentication and SMB lifecycle remain their existing owners; authored event times are preserved. All endpoint/server/network consumers share the planned occurrence times. Verify count/gap diversity, bounded ordered offsets, host/hour/seed separation, replay, both adapters, mounted siblings and terminal admission. Per-hour excitation resets are an explicit bounded approximation, not empirical long-term arrival calibration.

Secondary exact_regression: the HTTP profile validator added in37 passed an extra
model argument to validate_entry. Repair this validator boundary and add direct
network-policy validation tests plus a separately checked CLI run. Correct37/38
report claims: the saved invocations failed and were masked by later successful
commands in the shell cell; generated-data validation/eval results are unaffected.

Runtime blocker discovered by regeneration: Linux visible-shell bootstrap applies an
in-window floor, then its preferred readiness gap overwrites that floor with a new
pre-window start. Repeated boundary calls reject their own replacement and allocate
more shells until a PID lane is exhausted. Fix feasibility at the shared local-shell
timing owner for both session and loose-parent paths. If no visible replacement can
be ready inside the window, decline allocation and retain the existing valid parent;
when feasible, allocate once in-window and reuse. Preserve PID lanes/watermarks and
all ancestry/lifecycle guards. Verify server/workstation, both paths, repeated calls,
pre-window parent fallback and later visible replacement. This is an incidental
new_family runtime repair required to accept the selected SMB distribution change.
