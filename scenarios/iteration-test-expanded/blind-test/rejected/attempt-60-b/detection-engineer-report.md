# Detection Engineer - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 67
**Synthetic-Confidence Score:** 63

## Executive Summary

The dataset is highly realistic in many detection-engineering contracts: Windows Event IDs, Sysmon fields, Zeek UID joins, ASA connection lifecycles, and endpoint process/session ordering mostly hold up. I still assess it as likely synthetic because the mail telemetry contains concrete source-native artifacts: fixed Postfix delay-component ratios, visible queue lifecycle inversions, and one semantically invalid reject row.

## Evidence For Synthetic

- `distribution_texture`: Across 46 Postfix delivery rows, 41 have `delays=` components that round to the same ratio, about `0.18/0.08/0.22/0.52` of total `delay`. Real Postfix delay phases vary independently; this looks formulaic.
- `contract_gap`: `MAIL-CLIN-01.../syslog.log` queue `00026616B3C` has `postfix/qmgr ... queue active` at `13:55:36.501180Z` before `postfix/cleanup ... message-id` at `13:55:36.512259Z`.
- `contract_gap`: `MAIL-EDGE-01.../syslog.log` queue `00DD4DE517` has the same inversion: `qmgr` at `15:33:09.392327Z` before `cleanup` at `15:33:09.422013Z`.
- `schema_or_format`: `MAIL-EDGE-01.../syslog.log` at `16:07:01.180336Z` logs `NOQUEUE: reject: RCPT ...: 220 2.0.0 TLS go ahead`; `220 TLS go ahead` is a STARTTLS/session response, not a plausible RCPT reject status.
- `environment_or_collection_plausibility`: A few network/control rows begin just after the stated `18:00:00Z` end, e.g. ASA `Built` rows at `18:00:16`, `18:00:22`, `18:00:25` and Zeek connection starts after `18:00:00`. This is weak because boundary tailing can happen, but it does not fully match the profile wording for connection start timestamps.

## Evidence For Real

- Windows Security/Sysmon schema is generally strong: 4624/4634/4688/4689/4768/4769/5156 and Sysmon 1/3/5/7/10/11/22 carry expected field names, SIDs, logon IDs, process IDs, paths, and timestamps.
- DC account activity is coherent: `svc_mhsync` has 4720 creation, 4724 password reset, 4738 change, and 4726 deletion with a consistent SID.
- The `wevtutil cl Security` sequence is convincing: Security 4688 process rows, Sysmon process rows, ECAR process rows, and Security 1102 are all visible around `17:41:50-17:41:51Z`.
- Zeek protocol companion integrity is good: DNS/HTTP/SSL/SMTP/DHCP/NTP rows reference existing `conn.json` UIDs and their timestamps stay within parent connection intervals.
- ASA connection IDs show clean built/teardown pairing for visible lifecycle rows; unclosed built rows are limited to boundary-near records.

## Detailed Analysis

I parsed Windows XML event records across DC, servers, and workstations. Visible logon/logout ordering by `TargetLogonId` did not show impossible 4634-before-4624 cases, and Sysmon `ProcessGuid` dependencies did not show network/module/file/registry events after visible process termination or before a visible create for the same GUID.

The strongest defects are in Postfix. For queue `00026616B3C` on `MAIL-CLIN-01`, the `qmgr` active row precedes `cleanup` by about 11 ms. For queue `00DD4DE517` on `MAIL-EDGE-01`, `qmgr` precedes `cleanup` by about 30 ms. Minor syslog interleaving is possible in production, but `cleanup` is the component that prepares the queued message before `qmgr` activates it, so repeated inversions are suspicious.

The Postfix delay fields are more damaging: delivery rows repeatedly split total delay into nearly identical component ratios. Examples include `delay=6.80, delays=1.22/0.54/1.50/3.54` and `delay=9.49, delays=1.71/0.76/2.09/4.93`, both effectively the same proportions. That pattern is not how real SMTP queue, connection, and transmission phases behave at scale.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---:|---|
| `distribution_texture` | Mail/syslog | 41 of 46 Postfix delay rows | High |
| `contract_gap` | Mail/syslog | 2 queue lifecycle inversions | Medium |
| `schema_or_format` | Mail/syslog | 1 invalid RCPT reject status | Medium |
| `environment_or_collection_plausibility` | Network/proxy/firewall | Few boundary-after-end starts | Low |

## Realism Score by Category

- **Field format accuracy:** 72/100 - Strong Windows/Zeek/ASA fields, weakened by Postfix status semantics.
- **Temporal patterns:** 60/100 - Mostly coherent, but mail delay ratios and queue ordering look generated.
- **Cross-source correlation:** 84/100 - Zeek UID and endpoint correlations are notably solid.
- **Behavioral realism:** 74/100 - Host roles and activity are plausible; mail texture is the main tell.
- **Environmental consistency:** 76/100 - Collection profile mostly fits, with a small boundary-tail mismatch.

## Recommendations

- Generate Postfix `delays=` components independently from realistic queue, connection, and transmission timing distributions.
- Enforce Postfix queue lifecycle ordering: `smtpd client` -> `cleanup message-id` -> `qmgr queue active` -> delivery/removed.
- Use source-native SMTP reject statuses for `NOQUEUE: reject: RCPT` rows; avoid `220 TLS go ahead` in reject context.
- Clip or explicitly document post-window connection-start rows for Zeek, proxy, and ASA exports.
