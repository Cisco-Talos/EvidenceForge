# Routed examples and engine regressions

Local `dev` collected the routing follow-up at merge `c6dcf5fc`. The original
routing change was `e2864953`, based on `5fea57b4`. See the
[routing topology worklog](2026-11-23-studio-routing-topology.md) for the
forwarding and Studio changes in that first commit.

## Bundled examples and packs

- `05f28a36` ships routed 1.1.0 releases of Alderbrook Insider Exfiltration,
  Cedar Vale Invoice Phishing, Juniper Vale macOS DNS, Lantern Works Web
  Compromise, and Northstar Stolen Credentials. Each has authored routing and
  an edge ASA with NAT. Northstar uses Northstar Health 1.2.0. Lantern Works
  publishes its HTTPS portal from a DMZ through a static NAT address. The
  earlier example releases remain available.
- `087bc7c1` adds the routed Northstar Health 1.2.0 and MetroLink Specialty Care
  1.1.0 organization packs. `8c33c3e4` adds Talus Enterprises 1.0.0, with an
  engineering headquarters and a manufacturing site linked by a WAN.
- `74a39457` gives `tools/promote_pack.py` an install path for official
  published releases that preserves their release identities, rewrites
  dependency paths to bundled sources, and records their digests. The path for
  promoting personal releases reuses already-official industry dependencies.
  `c3f11599` keeps official ancestry, drops local copy notes and release-only
  configuration bindings, permits drafts from digest-indexed bundled releases,
  and rewrites copied file-set presets alongside share presets.

## Evaluator placement parity

`73212f1e` adds independent evaluator placement for authored forward and return
paths, static NAT, firewall traversal, and link TAPs. The parity rule in
[`AGENTS.md`](../../AGENTS.md) requires updating the evaluator counterpart and
hand-written expected-observer fixtures whenever engine routing, placement,
NAT, firewall forwarding, or capability rules change. The implementation and
fixtures are checked by `tests/unit/test_visibility_parity.py`.

## Generation behavior revisions

| Revision | Change |
| --- | --- |
| 572 | Bundled routed Northstar Health and MetroLink organization packs. |
| 573 | Denied or failed IMAPS reads retain network attempt evidence and omit successful Dovecot sessions. |
| 574 | HTTP responses use the standard reason phrase for statuses outside the built-in table. |
| 575 | ASA and eCAR validators declare native fields already present in output. |
| 576 | Routed bundled packs drop the release-only configuration binding, and copied packs remap their own file-set presets. |
| 577 | Bundled Talus Enterprises 1.0.0. |
| 578 | Deferred Mac shell commands must fit their GUI session. Mac SSH receiver qualification precedes routed attempts. The checkpoint inventory declares routing and VIP ownership as rebuilt state. |

## Regression repairs

The first focused run reproduced 20 default-tier failures. Legacy validation
tests now require the precise firewall advisory, the network validation fixture
includes authored routing, and endpoint-only fixtures omit their unused ASA
source. The legacy dispatcher test explicitly disables routing, and the
machine-account test constructs a real ASA emitter before checking teardown
timing. The scenario skill dispatcher fits its word budget.

The routed checkpoint regression checks a fresh topology after hydration and
the next PAT allocation. The macOS regression schedules a command before the
planned close with a shell execution later than the requested command. It
checks implicit and explicit shell parents with close times on either side of
shell readiness and verifies native process coverage.

## Local verification

All 20 original failures and the five new regression cases passed on `039cad07`.
Ruff lint and formatting and the behavior manifest check passed.
The full default suite passed with 21,373 passed, 134 skipped, and 2,504
deselected in 59m 38s, using loopback access and the macOS user temporary directory.

The exact Juniper Vale draft generated successfully from a user-provided copy at
seed `8801` with the default target and all eight configured format selections.
The `KR-MAC-04` census matched 46 forks, 52 execs, and 39 known exits, with zero
unresolved aggregate starts. The user removed the original managed draft through
the reviewed CLI deletion, and its original path was verified absent.

Native Studio integration tests need loopback sockets. The LaunchDaemon reference
test also compares the modeled account group with the process's primary group.
On this Mac, directories created under `/private/tmp` inherit `wheel`, while the
normal macOS user temporary directory inherits `staff`. The LaunchDaemon test
passed there with the original assertions.

The slow tier exercises generation from frozen releases and from drafts with
current defaults. The frozen Lantern Works 1.1.0 bundle generated and passed
evaluation acceptance, while the stricter example test found one Zeek
Internet TAP source-port mismatch and two Zeek X.509 capability disagreements.
Its scenario completeness score was 99.9723 against the test's 100 requirement.

## Follow-ups

- Add parity fixtures for the evaluator's encrypted-HTTP capability rule.
- Review and apply `requires_evidenceforge: <3.0.0` on bundled packs and scaffolds.
- Author an example scenario for Talus Enterprises.
- Review the personal Talos and Talus releases in the user workspace. Removal
  is optional and depends on the user's decision about those releases.
