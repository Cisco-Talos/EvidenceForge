# V2 Assessment Loops 11–20

## Loop 11 family contract — immutable Windows process authentication context

- **Owning abstraction:** Windows interactive logon/logoff action-bundle lifecycle plus the
  canonical `RunningProcess` authentication identity retained by `StateManager`.
- **Invariant:** A process termination preserves the username, SID, and LogonID established for
  that process at creation. Per-session `winlogon.exe` remains a SYSTEM/`0x3e7` process through
  teardown; the human LUID remains on session/logoff evidence and human-token children.
- **Entry paths:** baseline and storyline local interactive logons, RDP/Type 10 sessions,
  cached-interactive/Type 11 sessions, and late explorer bootstrap repair.
- **Consumers:** Windows Security 4688/4689, Sysmon process lifecycle, eCAR PROCESS
  CREATE/TERMINATE, session teardown ordering, and rendered auth-context probes.
- **Layer rationale:** process authentication identity is canonical process state, while the logoff
  bundle owns termination membership for a session. Rewriting Security or eCAR fields would only
  hide a state-model defect and would leave sibling sources inconsistent.
- **Sibling risks:** the fix must retain explicit teardown of the cross-auth SYSTEM `winlogon.exe`
  helper for both local and remote interactive sessions without terminating a shared boot process
  or losing child-before-parent ordering. Linux post-authentication enrichment is not changed.

## Loop 11 outcome

- Commit `4c7ea566`; full suite `5,959 passed, 22 skipped`; deterministic evaluation
  97.18870689794775 over 90,553 records with acceptance passed.
- The hard probe found zero Security or eCAR winlogon auth-context/session-ID mismatches. The
  targeted family did not recur in blind review.
- Initial blind synthetic-confidence scores were 91/79/74/32 (average 69.0). Deliberation revised
  the panel to 89/75/79/78 (average 80.25), unanimously Synthetic.
- Next target: durable proxy tunnel lifecycle cardinality, with Linux session-scoped parent
  ownership and source-native IPv6/path rendering immediately behind it.

## Loop 12 family contract — durable explicit-proxy tunnel lifecycle

- **Owning abstraction:** `BrowserSessionActionBundle` owns the planned same-origin HTTP request
  group; `ProxyTransactionActionBundle` owns the physical client-to-proxy CONNECT transport and
  its bounded application reuse state.
- **Invariant:** a successful inspected HTTPS tunnel has one durable CONNECT transport identity
  and may carry zero, one, or multiple request occurrences. The physical transport ledger and
  lifetime reserve the browser group's planned request capacity, while every proxy access row
  retains request-local method, URL, body, status, and byte semantics. Reuse never exceeds the
  reserved bytes, request count, close time, host, destination, or user-agent boundary.
- **Entry paths:** ordinary browser page-load groups, route-profile browser sessions, direct
  explicit-proxy HTTPS requests, authored connections, cache hits, denials, and tool/service
  clients. Only browser-style follow-on transactions with explicit group depth may consume a
  planned reusable tunnel.
- **Consumers:** proxy access CONNECT/request rows and tunnel IDs, the client-side Zeek/ASA/eCAR
  transport tuple, source-port allocation, proxy-origin evidence, HTTP transaction depth, and
  deterministic hard probes over request-count distributions.
- **Layer rationale:** the browser bundle already computes group counts, aggregate bodies, and
  group duration; the proxy bundle is the sole owner of explicit CONNECT transport identity and
  capacity. Emitter-side row grouping or fabricated reuse would not repair the canonical
  transport contract.
- **Sibling risks:** do not double-count large uploads, let aggregate tunnel bytes fall below
  visible child rows, reuse across user agents/hosts/errors, move requests beyond transport close,
  or create a second client transport for a reused request. Preserve setup-only and one-request
  paths alongside multi-request groups.
