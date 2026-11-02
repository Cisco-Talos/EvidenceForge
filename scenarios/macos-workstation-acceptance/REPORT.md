# Mac workstation acceptance: initial measurement

**Full workload: BLOCKED.** The unchanged source stops at the real catalog
Chrome launch. There is no accepted full-workload bundle, and the controlled
reference app has not been substituted for Chrome.

The supported combined diagnostic generates **29 forks and 34 execs**, with
matching independent identities, zero aggregate starts and **75 native ES rows**
(including 12 known exits). Its eCAR output agrees with those process counts.
This is useful process evidence, but the diagnostic omits the blocked Chrome
family and explicitly requests partial coverage. It is not the acceptance target.

## Activity coverage

Counts below are actual canonical obligations and committed native records from
separate diagnostic slices. They include common startup and any baseline in that
slice, overlap across runs, and must not be summed.

| Activity | Forks expected / native | Execs expected / native | Result |
| --- | ---: | ---: | --- |
| Apple Terminal plus local commands | 5 / 5 | 6 / 6 | Covered |
| iTerm2 plus local commands | 6 / 6 | 8 / 8 | Covered |
| Non-PTY Mac-to-Mac SSH plus remote command | 11 / 11 | 12 / 12 | Covered |
| PTY Mac-to-Mac SSH plus remote command | 12 / 12 | 14 / 14 | Covered |
| Chrome main, renderer, GPU, network helper and browsing | Unknown | Unknown | Generation rejects before qualified app startup |
| Two background OS-inventory job activations | 2 / 2 | 4 / 4 | Covered after repair |
| Baseline at primary seed 373 | 0 / 0 | 0 / 0 | Not exercised; zero does not establish baseline coverage |
| Combined supported diagnostic | 29 / 29 | 34 / 34 | Covered subset; full target remains blocked |

Every successful slice has matching fork/exec identity fingerprints, not merely
matching totals. The measurement also checks required executable roles, authored
process PID/image evidence and whether intended steps actually ran. A failed run
has **unknown counts**, not a fabricated zero denominator.

The initial low-intensity source scheduled no user-activity timestamps at seed
373. Intensity was raised to medium during initial workload construction to
exercise background activity; the seed, time window and all target activities
were retained. The primary run still has no in-window background starts. Two
predeclared supplementary baseline seeds are retained in full: 374 is also
quiet; 375 has **5 forks/7 execs**, including terminal/helper startup, with exact
native reconciliation and no aggregate births. Those runs demonstrate the path,
but do not replace primary-seed acceptance or remove its unexercised condition.

## Repairs driven by this workload

1. **Useful system job:** the existing root launch mechanism now accepts the
   already modeled `/usr/bin/sw_vers` image for OS inventory. It retains that
   image's own metadata rather than copying true's flags. The reference observed
   true; this extension is an explicit synthetic model using shared launch facts.
2. **Final-pass process activity:** Mac baseline process starts are no longer
   omitted simply because their natural exit may be after collection. Their
   existing owners retain lifetime responsibility. Starts displaced beyond the
   output boundary by pacing reject before process materialization.
3. **Authored/background ordering:** due authored GUI/SSH owners execute before
   background activity at that simulated time. Future logoffs stay pending.
4. **Baseline terminal producer:** selecting Terminal/iTerm2 from the catalog
   uses the native startup/reuse owner. It no longer creates an aggregate app
   which later looks like an unsupported existing-app window.
5. **Truthful visibility:** pre-collection setup stays in state/history but is
   marked outside collection. A logoff without a matching session is a no-op,
   not emitted evidence. Ground truth preserves subsecond occurrence precision.

The last repair fixes measurement errors, not missing native process rows. The
first combined evaluation failed because it expected setup and no-op logout
traces. After correcting those status records, deterministic evaluation passes
all applicable hard gates: **89.53 overall**, **100% native format conformance**,
**100% cross-source field agreement**, and **100% intent reconciliation**.
This is not a blind realism assessment or universal authenticity claim.
Native-only filtering of this corrected combined diagnostic produces nonempty,
byte-identical ES output. All 15 selected terminal/SSH/job public CLI and recovery
regressions pass. Full-workload recovery remains blocked with Chrome.

## Remaining blocker and evidence needed

Chrome currently has catalog paths/role arguments but lacks the complete native
main/helper metadata and launch plans needed for this workload. The first
failure is the absent Finder app/bundle policy. Adding that name alone would not
resolve installed signing/entitlements, runtime security/slice, descriptor tables,
or helper parent/responsibility and execution relationships.

Existing Finder and terminal references establish reusable OS launch behavior.
The next reference should target **one clean Chrome launch and its renderer,
GPU and network helpers**, using a disposable unsynced test profile and controlled
local content. It should classify those remaining facts without exposing paths,
environment values, browsing history, account data or native records. No such
collection or private-log read was performed for this measurement.

Public Chromium sources are useful inputs, not evidence of the frozen catalog
release's runtime state: the [signing documentation](https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mac/signing/README.md)
distinguishes official Chrome and development signing; the
[renderer entitlement template](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/helper-renderer-entitlements.plist)
includes JIT permission. Helpers cannot safely inherit the reference app's null
entitlements or a parent's signing facts.

## Limits and next acceptance condition

Full acceptance requires Chrome and its helpers to work in this same source,
positive exercised baseline coverage, all intended activities realized and
exact canonical/native reconciliation, followed by full-workload filtering and
recovery checks. Current component recovery tests and successful diagnostic
filtering do not close that gate.

The ES profile covers fork, exec and known exits; generic teardown and some
command outcomes remain unknown, so exit coverage is incomplete. It does not
generate native ES file/network callbacks. Unified Log remains limited to its
qualified workspace-entry and policy-refusal families; no browser-launch or
launchd messages are inferred. Those limits remain separate from fork/exec
completeness.

`RESULTS.json` retains source/manifest hashes and measured counts. Generated
bundles and all synthetic rows stay outside the repository. Reproduce the
measurement with the command in `README.md`; no host collectors are involved.
