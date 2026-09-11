# Iteration Test Blind Assessment — Loop 73

## Outcome

Loop 73 moved modeled fresh Kerberos AS/TGS acquisition far enough ahead of the successful logon
and target-service traffic that consume it. The automated evaluation scored 96.4776 PASS across
127,848 records. Initial blind synthetic-confidence scores were 70, 64, 64, and 67 (mean 66.25).
All four experts returned Synthetic verdicts, average verdict confidence was 80.75, and the score
spread was 6, so deliberation was not triggered.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 82 verdict confidence, 70 synthetic-confidence. Fleet-wide Linux
category quotas, catalog-shaped Sysmon metadata gaps, and unexplained NewCredentials token use
across unrelated parent processes outweighed strong source correlation and role-shaped traffic.

**Detection Engineer:** Synthetic, 76 verdict confidence, 64 synthetic-confidence. The leading
finding was 97 SMB-derived Zeek file rows carrying MD5/SHA1/SHA256 values while declaring only the
MIME analyzer. All-dash Sysmon enrichment and a missing 4722 account-enable companion reinforced
the verdict.

**Network Forensics:** Synthetic, 81 verdict confidence, 64 synthetic-confidence. Transport and
multi-sensor behavior were strong, but simplified multi-megabyte SYSVOL/NETLOGON objects,
request-varying byte counts for nominally immutable hashed web assets, and one invalid-looking OCSP
relationship favored synthetic origin.

**Host/EDR Forensics:** Synthetic, 84 verdict confidence, 67 synthetic-confidence. The reviewer
identified missing reverse-shell descendants, incorrect shell-redirection file ownership, and
three `runas /netonly` executions with 4648 evidence but no requested child process, while finding
the wider process and lifecycle corpus production-like.

## Fix Verification

- 210 fresh Kerberos bundles joined across Windows Security and Zeek using same-account,
  same-client, contemporaneous AS/TGS and exact source-port transport evidence.
- Zero joined bundles rendered the latest KDC transport observation, 4768, or 4769 after the
  dependent target-service flow or successful 4624.
- The minimum latest-KDC-to-earliest-service margin was 1.254 seconds; median margin was 2.201
  seconds.
- Behavior revision 37 records surface digest
  `c6916d584af620a5a0081c7701b8443765d2b8a6fddacd33b0ba9238c2d2a66f`.
- The routine gate passed 8,405 tests with 5 skips and 2,009 deselections; focused Kerberos and
  behavior-manifest tests and Ruff checks passed.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The Loop 72 Kerberos acquisition inversion did not recur in any initial expert report.

## Prioritized Improvements

### P0 — Preserve executable and shell process semantics

Route encoded reverse-shell pipelines, shell redirection, and `runas /netonly` through process
action bundles that own every required child, parent, file-open, credential, and network effect.
Do not attach descendant behavior to a wrapper executable or publish successful explicit-credential
execution without the requested child or an explicit failure outcome.

### P1 — Make Zeek file-analysis provenance authoritative

Whenever a Zeek file row carries MD5, SHA1, or SHA256, include the corresponding analysis stage in
the row's analyzer provenance. Otherwise omit the digest. Enforce this for SMB, HTTP, SMTP,
certificate, and other file-observation entry paths from one shared contract.

### P1 — Replace catalog-shaped Sysmon enrichment fallback

Populate stable build/image metadata and configured hashes for known Windows and signed-vendor
binaries. When enrichment fails, make the failure sparse and field-specific instead of assigning
all metadata and hashes the same `-` sentinel for every occurrence of an image.

### P1 — Diversify durable content and Linux background texture

Give cacheable web entities stable length/content identities across requests and vary Linux daemon
activity by role, installed software, and logging policy. Remove fleet-wide 8/5/4 category caps and
headless-server desktop hooks unless the host inventory supports them.

### P2 — Complete lower-volume native contracts

Emit the 4722 enable event when the modeled account visibly transitions from disabled to enabled;
gate OCSP on coherent issuer/AIA relationships; keep SSH observation decisions lifecycle-coherent;
and make SYSVOL/NETLOGON paths and sizes type-appropriate.

## Priority Rationale

The process-semantic contradictions are the strongest disbelief anchors, but they span several
architectural execution families. Loop 74 takes the repeated 97-row Zeek provenance defect first:
it is a specialist-confirmed source-native contract with broad entry paths, high frequency, low
implementation risk, and an exact rendered-output probe. The process family remains the leading
architectural target after that bounded repair.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.4776: 99.9992 parseability, 96.8531 plausibility, 94.4742
causality, and 93.2302 timing. It did not flag the Zeek analyzer/digest provenance contradiction,
process-execution semantic gaps, Sysmon enrichment boundary, durable web-entity variation, or
fleet-wide Linux category quotas identified by the panel.
