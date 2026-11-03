# Current Mac workstation acceptance

The bounded process-start milestone is complete. Every modeled in-window fork
and successful exec in the two-Mac acceptance matrix reconciles with native ES,
with zero aggregate starts. The original thirty-minute source and seed are
unchanged; quiet baseline sampling and positive companions remain separate.

| Current revision 376 run | Forks / native | Execs / native | Native exits with known result | Unknown exit observations | Background execs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Thirty-minute primary, seed 373 | 33 / 33 | 39 / 39 | 13 | 13 | 0 |
| Three-hour recovery companion, seed 373 | 45 / 45 | 55 / 55 | 13 | 32 | 16 |

Unknown counts are ingress coverage observations, not a universal census of
all terminal results. Start completeness does not imply exit-result completeness.
The source omits native exit rows when the canonical result is unknown. The new
literal `uname -a` nominal policy adds one known natural completion; it cannot
apply to other arguments, replaced images, truncated commands or session teardown.
Directory-listing, GUI shutdown and SSH final-worker results are not assumed zero.

Both runs realize all authored activities and required executable/argument roles:
Apple Terminal, iTerm2, local queries, SSH with and without a PTY, Chrome main and
renderer/GPU/network helpers, browsing and OS-inventory jobs. The original,
predeclared supplemental seed 375 also exercises positive baseline activity;
its revision-374 results remain historical and are not relabelled as revision 376.

The recovery companion passes public suspension, read-only verification and exact
resume with retained SSH continuations and live terminal/browser/helper work.
All **22 deterministic bundle files** match uninterrupted generation, and native-only
filtering preserves identical ES and ULF bytes. Neither source coverage nor recovery was
made to pass by removing workload families or weakening the complete ES policy.

Deterministic evaluation verifies both authoritative bundles and passes applicable
hard gates: primary **88.9114/100**, recovery **88.7091/100**. These scores do not qualify
unimplemented native templates. The small lab retains low noise-volume/diversity
limitations. The independent whole-process census and required executable/argument checks pass.
A bounded review of all three synthetic ULF rows confirms the workspace family and
root sshd-session PAM writer, actual peer tuple, static/private callsite and modeled
main-image frame. No new blind panel or assessment loop was started.

**The endpoint delivery sequence is not fully complete.** This workload now emits
three ULF rows: two loginwindow workspace entries and one successful keyboard-interactive/
PAM authentication. Seed 373 selects password for non-PTY and public-key for PTY;
public-key authentication is not assigned a false PAM-success row. A separate real-engine
password-intent PTY check passes through the shared authentication producer. The
separately qualified ASP policy-refusal source also remains available.

PAM/session-open-close, disconnect, public-key success and launchd ULF messages remain
unqualified. The launchd test retained zero rows; its narrower message-only selection
has a code-tested correction but no native rerun or promoted template. Unknown GUI/SSH
exit outcomes remain explicit lifecycle limits. Current deterministic acceptance covers
the implemented families and does not close those remaining native evidence gates.

See the finite [four-phase delivery plan](../../docs/design/macos-workstation-feasibility/endpoint-delivery-acceptance.md)
and [current machine-readable results](CURRENT-RESULTS.json). The previous
[Chrome integration results](CHROME-RESULTS.json), [initial report](INITIAL-REPORT.md)
and [original slice results](RESULTS.json) remain dated historical evidence.

All data in these runs is synthetic. Native records are not committed or copied into the repository. Only explicitly
authorized offline reviewers read private captures and returned closed comparison labels. No product release version changed.
