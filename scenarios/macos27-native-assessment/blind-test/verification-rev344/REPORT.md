# Deterministic verification after the selected development fixes

Source commit `54e5a8ab`, behavior revision 344, authored seed 327. This is a fresh synthetic
verification bundle, **not another blind assessment loop**. The loop-1 scores are unchanged;
there is no post-fix authenticity score or full-native-coverage claim.

Generation completes with **10,634 records**. All hard evaluation gates pass, parseability is
100, and the aggregate automated score is **90.1802**. The existing anomaly-rate, short-window
regularity and volume warnings remain. No evaluation threshold was weakened or optimized away.

Rendered-output checks:

- All five nested-shell command steps execute through canonical fork/exec ownership.
- Native ES contains eight forks, four execs and two known exits. The two qualified query
  exec-to-exit intervals are 0.092647 and 0.093163 seconds, both with successful status.
- The six paired simple diagnostic lifetimes in the bounded eCAR probe are all subsecond:
  median 0.18 seconds, maximum 0.379 seconds. Activity counts differ from the prior bundle
  because canonical scheduling and RNG consumption changed; this is not a same-record A/B study.
- All 2,095 TCP/UDP connection rows have zero repeated once-only directional history classes.
- All 852 TLS rows use the passive direction/visibility contract; no uppercase ServerHello
  appears and no client-only handshake claims a negotiated version.
- The private source-ingress spool is removed before successful bundle completion.

Final verification includes source filtering and nonempty native checkpoint verification,
suspended resume and exact uninterrupted-output comparison. Focused activity/command/protocol
checks, baseline contracts, corrected fixture/source-inspection tests, skill contracts, config
validation, Ruff and behavior checks pass. The complete run had 17,210 passes and four failures;
all four were corrected or verified in fresh focused processes, as detailed in the worklog.
It is not reported as a later fresh zero-failure full run.

The selected implementation work is complete and exits the fix/review cycle here. No additional
reviewer findings are automatically selected. Remaining native GUI application launch coverage
requires the separate responsibility/launch reference proposal; broader file/auth, helper/PTY,
entitlement/full-hash and native message families retain their qualification boundaries.
Raw generated data and all private captures remain outside Git.
