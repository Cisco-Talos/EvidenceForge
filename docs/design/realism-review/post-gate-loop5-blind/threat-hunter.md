# Threat Hunter — Blind Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict confidence:** 96/100
- **Synthetic-confidence score:** 96/100

## Executive summary

The reviewer described the corpus as exceptionally well correlated and largely source-native, but
classified it as synthetic because component-owned Windows file paths were repeatedly paired with
unrelated processes and because dynamic PAT state sometimes closed before its TCP connection. The
reviewer did not reproduce any of the session, PID, SSH ordering, Windows-field, record-ID, or
startup-module defects repaired by gate loops 1–5.

## Evidence supporting synthetic

- Five dynamic translations close at build time while their unanswered TCP connections remain
  open until a 30-second SYN timeout. Connection `1206876` is the representative case: ASA lines
  12–16 and Zeek connection line 15 preserve the entire incompatible lifecycle in-window.
- Windows ambient file activity combines a compact path pool with unrelated processes. Examples
  include `lsass.exe` writing Defender DetectionHistory, `csrss.exe` and `winlogon.exe` writing
  Windows Update CAB files, and `ChromeSetup.exe` writing SoftwareDistribution artifacts.
- The static path confirms that baseline `_emit_ecar_file_churn()` selects an arbitrary running
  process before `select_ambient_file_churn_effect()` draws from the generic Windows path pool.
  This is an ownership-model defect rather than an emitter formatting error.

## Evidence supporting real

- All reviewed JSONL and Windows XML parsed, and Windows record identifiers remained ordered.
- All 1,023 DNS, 649 HTTP, and 1,011 TLS rows referenced valid Zeek connection UIDs; all 554 TLS
  certificate references resolved.
- Of 598 Windows eCAR process creates, 594 matched Sysmon Event 1 within five seconds with no image
  disagreements. No known process actor was referenced after termination.
- SSH transport, source endpoint, target endpoint, authentication, and command evidence correlated
  cleanly for the sampled sessions.

## Scores

| Category | Score |
|---|---:|
| Field format | 96 |
| Temporal realism | 88 |
| Cross-source correlation | 98 |
| Behavioral realism | 55 |
| Environmental realism | 66 |

## Disposition

The PAT lifecycle claim is accepted into Batch 3. The file-ownership claim is accepted into Batch
4's world/distribution-state work. Neither is a regression in the bounded post-Batch-2 gate scope.
