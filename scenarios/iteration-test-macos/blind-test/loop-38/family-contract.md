# Linux sudo/PAM phase timing

Classification: sibling_defect; family_level. Owner: LinuxSudoSessionActionBundle plus named timing relationships. Baseline and any canonical sudo-session caller must consume one scoped microsecond-resolution plan for process lead, command/PAM open, child readiness, close and termination. Native syslog and eCAR render the same bundle phases; emitters add no jitter. Preserve invoking principal, TTY serialization, lifecycle identity and termination ordering. Close-headroom admission derives from the same configured upper bounds rather than a stale fixed bound. Denied standalone commands remain outside this allowed-session bundle. Direct bundle callers receive an isolated compatibility runtime; production explicitly injects the engine runtime. Verify all phases, same-seed replay, changed seed separation, zero-runtime boundary, configured headroom and baseline/explicit-source siblings. This does not change authored Mac command offsets or SSH authentication phases.

Secondary exact regression: unconfigured syslog entries must not resolve the opt-in
arrival sampler. Broader admission fixtures caught an eager runtime access added in36;
keep the optional profile boundary lazy and preserve literal-cap sibling execution.
