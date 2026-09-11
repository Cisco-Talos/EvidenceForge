# Iteration Test Blind Assessment — Loop 62

## Outcome

Loop 62 removed the visible zero-padded 32-bit identifier fingerprint across proxy tunnels,
compiled storage/eCAR files, and Postfix queues. The automated evaluation scored 97.2286 PASS
across 129,460 records. The current-model blind panel was unanimously Synthetic with initial
scores 68, 58, 89, and 74 (mean 72.25). The required deliberation reconciled the 31-point initial
spread and produced final scores 76, 70, 89, and 80 (mean 78.75).

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 82 verdict confidence, 68 initial synthetic-confidence; revised to
88 and 76. Four SSH receiver/continuation sessions used contradictory numeric identities between
eCAR and near-simultaneous systemd-logind removal records, while neighboring SSH sessions joined
correctly. Repeated Linux daemon-count templates and two atypical Windows execution ancestries were
secondary findings.

**Detection Engineer:** Synthetic, 72 verdict confidence, 58 initial synthetic-confidence; revised
to 82 and 70. DC-01 rendered a legacy Event 4698 schema despite Server 2022 build evidence, and its
enabled hourly task lacked task-parented execution at the expected triggers. The reviewer otherwise
found unusually strong parser, field, lifecycle, Zeek, ASA, certificate, and process correlation.

**Network Forensics:** Synthetic, 94 verdict confidence, 89 synthetic-confidence before and after
deliberation. Dozens of AAAA answers retained noncanonical padded hextets and shared a templated
`::1` suffix. All Zeek files were start-time sorted, legitimate TXT queries were role-inappropriate
and synchronized, A/AAAA order was universal, and the routed UDP long tail lacked NTP.

**Host/EDR Forensics:** Synthetic, 88 verdict confidence, 74 initial synthetic-confidence; revised
to 91 and 80. UFW records implied an exact noon boot anchor plus uniform 0–250 ms residuals and
reused three-value TCP-window fingerprints. SSH/RDP authentication timing occupied narrow bands,
all 849 Event 4689 statuses were zero, and fleet cron texture was highly regular.

## Fix Verification

- All 1,964 proxy rows carrying tunnel IDs match `PT-` plus 16 digest-derived hex characters;
  none use the former `PT-00000000...` shape.
- All 111 rendered compact eCAR storage-file references match 16 digest-derived hex characters;
  none use the former `file-00000000...` shape.
- The 138 Postfix lifecycle rows use 30 stable 9–11-character uppercase queue IDs. Five rows begin
  with zero as ordinary entropy, rather than every queue being zero-padded.
- The fixed identifier family did not recur in any expert report.

## Prioritized Improvements

### P0 — Unify SSH continuation and source-local lifecycle identity

Four visible receiver/continuation sessions close under different eCAR and systemd-logind IDs.
Route every SSH transport, authentication, PAM/logind, endpoint session, transfer, and close path
through one authenticated continuation identity. Apply observation decisions coherently to the
source-local open/close lifecycle and add a rendered cross-source contract probe.

### P0 — Canonicalize and diversify public IPv6 identity

Normalize every AAAA answer through an IPv6 address owner before rendering, then replace the one
random-hextet-plus-`::1` construction with provider/service profiles and varied interface IDs.
Verify canonical text and repeated DNS-to-connection identity at every sensor.

### P1 — Repair UFW host-clock and scanner identity texture

Derive kernel monotonic timestamps from persistent non-round host boot identities and skewed queue
latency. Bind TCP stack fingerprints to scanner identities and broaden external source and port
populations with heavy-tailed recurrence.

### P1 — Add realistic process termination outcomes

Make canonical process outcomes own Security 4689 status, including ordinary command failures,
updater/service return codes, and rare abnormal exits, while preserving terminate correlation.

### P1 — Bind scheduled-task schema and execution to host build and task state

Render modern Event 4698 fields for modern hosts and model either task-parented execution at valid
triggers or explicit missed/disabled/failed/deleted outcomes.

### P1 — Broaden authentication and network-background timing

Use authentication-method, backend, host-load, negotiation, and route inputs for long-tailed SSH
and RDP delays. Place legitimate TXT traffic on role-appropriate resolvers, diversify A/AAAA order,
and add topology-consistent NTP and sparse UDP traffic.

### P2 — Preserve source-native export and observation semantics

When output represents native Zeek logs, order connection records by close/log-write behavior. Keep
HTTP FUID and files rows lifecycle-coherent unless explicit per-log export loss is modeled, and vary
routine Linux daemon counts by uptime, packages, role, and maintenance state.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.2286: 99.9992 parseability, 96.4484 plausibility, 97.2176
causality, and 94.0615 timing. It confirmed acceptance, source conformance, causal ordering, field
agreement, and IDS integrity. It did not detect the SSH identity substitution, noncanonical IPv6
grammar, native Zeek ordering, UFW boot-anchor texture, all-zero process outcomes, Event 4698 schema
era, or role/timing distributions identified by the panel.
