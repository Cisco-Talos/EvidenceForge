# IDS signature overlays

## File and overlay

Package defaults live in `activity/ids_signatures.yaml`. Project changes belong
in `.eforge/config/activity/ids_signatures.yaml`. Entries merge by `sid`, so an
overlay can add a signature or replace selected fields, including its default
alert policy. Start a new CLI process after edits, then run
`eforge validate-config --json`.

Inspect the effective catalog with `eforge info ids_signatures` before selecting or changing an
entry. The text form lists valid SIDs with concise transport and message context; `--json` exposes
the compact structured catalog when exact compatibility fields are needed.

```yaml
signatures:
  - sid: 2002910
    alert_policy:
      event_filter:
        type: both
        track: by_src
        count: 5
        seconds: 60
```

Required signature fields remain `sid`, `rev`, `message`, `classification`,
`priority`, and `proto`; the existing `dst_port`, `direction`, DNS templates,
target service/OS, and baseline eligibility fields keep their current meanings.

## `alert_policy`

`alert_policy` is optional. Omission and `every` both admit every sensor-visible
candidate. A policy object supports:

```yaml
alert_policy:
  detection_filter:
    track: by_src       # by_src | by_dst
    count: 5            # positive integer
    seconds: 60         # positive integer; half-open window
  event_filter:
    type: limit         # limit | threshold | both
    track: by_src
    count: 1
    seconds: 300
```

`detection_filter` suppresses the first `count` rule matches and admits later
matches while the rolling window stays above that threshold. `event_filter` is
then applied to admitted matches: `limit` emits the first `count` per window,
`threshold` emits every `count`th match and resets, and `both` emits once when the
count is reached and suppresses until expiry. A timestamp exactly `seconds`
after the window start begins a new window.

Scenario attachment policies replace, rather than merge with, this default.
Use `policy: every` on an attachment to explicitly bypass a signature default.
EvidenceForge models alert output only: it does not parse complete Snort rules,
apply `rate_filter`, CIDR suppressions, or IPS actions.

Signature defaults are inherited by attachments on typed `connection`,
`beacon`, `ssh_session`, `rdp_session`, `dhcp_lease`, `port_scan`, `web_scan`,
`dns_query`, `dga_queries`, and `dns_tunnel` events. Defaults never make an
unattached tuple alert. The IDS model does not decrypt traffic, and mail-event
attachments remain deferred.

## Validation

`eforge validate-config` rejects empty policies, unknown keys, invalid
filter/type/track values, booleans/fractions/non-positive values, and integers
above 2,147,483,647. `eforge validate <scenario>` rejects unknown or duplicate
attachment SIDs and conflicting effective policies for one SID. Protocol, port,
and direction mismatches are advisory warnings because nonstandard deployments
can be intentional.

Alert cadence, attachment, and inspection visibility are semantic choices. Do not add or change them
merely to remove a warning; ask when the user did not specify the intended policy. A project overlay
cannot authorize decryption, OOB behavior, or evaluator-policy changes.

## `snort_classifications.yaml`

The `classifications` mapping resolves a signature's classtype identifier to the source-native Snort
display description. Supplying this root replaces the entire packaged mapping, so copy every
classification before changing one description. It does not add alert logic or attach a signature
to traffic. Keep identifiers aligned with `ids_signatures.yaml`, and do not rename a classtype merely
to change presentation text.
