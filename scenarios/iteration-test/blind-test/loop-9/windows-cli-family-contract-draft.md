# Windows CLI parent lead: invocation identity (draft)

Recurring unfixed distribution_texture from loop1 and independently Host/panel6:
fresh cmd/PowerShell→SSH pairs reproduce destination/actor-specific delays within
milliseconds hours apart. The root helper hashes host,user,session,command for
both shell preference and lead but omits the invocation. Stable shell preference
is compatible with user habits; fixed repeated launch latency is not required.

Owner: ActivityGenerator._ensure_windows_user_cli_parent canonical placement and
existing BaselineTimingPlanner typed runtime. Invariant: independent invocations
have bounded, nonuniform launch preparation durations scoped by full occurrence
identity; replay of the same intent is deterministic. Parent selection, session
readiness, source-visible admission, foreground occupancy, shell/client lifetimes
and transport ordering remain intact. Resident shells may be reused where valid;
dedicated SSH/SCP/SFTP shells remain separate. Keep stable shell-family preference
separate from per-invocation timing. Do not jitter Windows/XML/eCAR renderers.

Entry paths: explicit/baseline Windows CLI launches; SSH, SCP, SFTP client bundles;
compatibility process-parent inference and preflight; typed authored process
commands requiring user CLI parents. Consumers: canonical process creation/PPID,
Security4688/Sysmon1/eCAR, session end holds, source timing/deadlines and process
lifetime/endpoint network ownership. Raw identities unchanged.

Plan: use existing shared typed right-skew duration planner within current1.2–6s
support; stable identity adds actual child occurrence time plus host/user/session/
command, while shell choice keeps existing preference seed. Check prepared timing
and rejection side effects before adoption. Source-visible parent/child deadlines
must still admit/reject the complete chain; do not relax readiness or repair late
FLOW by delaying transport past authentication. The bounds are modeled support,
not empirical Windows calibration. At earliest session boundaries retain explicit
causal graph/window semantics rather than inventing evidence before authentication.

Sibling proof: repeated same command invocations (SSH/SCP/SFTP/other user CLI),
replay/scope isolation/no global RNG use, source-bound rejection with no desktop
bootstrap mutation, resident/dedicated parent behavior, netonly/RDP session holds,
Windows transport-before-auth and source-native Sysmon/eCAR interval populations.
