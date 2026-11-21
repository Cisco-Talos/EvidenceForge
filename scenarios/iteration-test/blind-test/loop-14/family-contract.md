# Dovecot session identity from canonical connection facts — draft

New panel12 distribution_texture verified at owning implementation: current
_dovecot_session_token takes _stable_seed32, encodes an integer into base64-like
characters and pads to10withA. All18renderedtokens10charsAAAAprefix. Do not label
prefix alone as impossible real-world origin; model/source mismatch is independently
confirmed against Dovecot2.3.21andcurrent main client_get_session_id algorithm.

Primary source (read November20):
https://raw.githubusercontent.com/dovecot/core/2.3.21/src/login-common/client-common.c
https://raw.githubusercontent.com/dovecot/core/main/src/login-common/client-common.c
Algorithm takes low48bits epochmicroseconds in little-endian, remoteport little-
endian2bytes, network-orderIPv4(4)/IPv6(16), then normalbase64. Client caches one ID
and reuses it across login/session records. Encoding constants are protocol/source
semantics, not tunable enumerable vocabulary or a random pool.

Proposed owner: EmailAccess action bundle canonical transport handoff plus source-
native Dovecot identity helper. Use existing NetworkConnectionIdentityCapture to
obtain committed exact transport tuple/start, not last-event globals, arbitrary
new port, State UID lookup that may already be closed, or rendered conn row. Token
computed once at canonical server-login time, passed unchanged to login/logout.
Canonical transport comes from shared network bundle; no sibling source triggers.

Entry inventory: generate_email_read typed storyline and baseline mailbox access
both delegate generate_email_access -> EmailAccessActionBundle -> common executor.
Linux imaps calls _emit_dovecot_imap_syslog; OWA/Exchange/Windows and unsupported
POP3/session-proxy paths are outside this helper and must remain unchanged.
Consumers are login and disconnect source-native syslog rows. Ephemeral local reuse
needs no unbounded cache/checkpoint state. Preserve unrelated existing32bit seed/RNG
for worker/timing/byte sampling; only session identity changes. New token helper pure
explicit facts (datetime,clientIP,remoteport), validate range/address; integer delta
toUTCepoch avoids float timestamp rounding; native48bit wrapping intentional.

Risks: actual generated transport may start after requested intent; neverderiveport
from requested/preview facts. Use typed captured transaction, canonical positive
login anchor >=transportstart and withinclose. Existing SMTP/IMAP lifecycle may use
requesttime; investigate before changing timing (avoid unrelated retiming). Native
IPencoding IPv4mappedIPv6 should follow actual family, no silentnormalization. One
physical imaps session token stable across rows, different clientports/addresses/
µstimes decode differently; primary-source algorithms can legitimately share some
bytes/prefixes. No arbitraryrandomness or “noAAAA” assertion.

Gates before production: pure decode fixtures IPv4/IPv6,subsecondexactness/wrap,
range rejection; capture exact transport handoff positive/negative/mismatch tests;
login/logout reuse, native connection tuple/time agreement, unchangedOWA, native
freshprocess replay/checkpoint/RNG/Ruff. Actual loop13 newly generated timing data
must finish first; no14production code yet. Draft may be superseded by13findings.

Isolated qualification before production: 11pure checks pass (including missing/
mismatched capture rejection, actual-later transport anchor, exact token bytes),
2native4minute IMAPS/OWA cases pass (9with initial7unit,13token calls),34default
email checks pass30deselected. Positive counters ensure active path. Prototype
stored inTMPonly, source engine546frozen through13post. Native current version is
still old until production applied. Refined implementation uses actual committed
transport interval for existing server worker/login/logout timing because requested
intent may precede connection execution. No new session lifecycle architecture,
POP3 capability or arbitrary source jitter. Capture/client/server/protocol/outcome/
positive-close checks prevent publishing a fabricated successful mail login.
Native byte algorithm is invariant, no new config pool needed.

Selected production design after isolated proof, pending application after13post:
use same existing helper with explicit typed facts; keep canonical capture local
only for Linux IMAPS, narrow `capture is not None` before consuming transaction,
validate exact UID then tuple/outcome/positiveclose/remoteport before allocating
mailworker. Nativecodec validates port at its own boundary. No new helpercache or
mutable global handoff; no changes to raw Syslog emitter. Preserve original seed
for other per-session details, now scoped to actual connection execution anchor.
Implementation applier preparedTMPonly; must apply then qualify without monkeypatch,
bump generation behavior, checkpoint/RNG/Ruff/native/replay and real14bundle.

## Native-run correction: static NAT is a valid server binding

First547canonical attemptfailed on destination equality, not identity codec.
Diagnostic confirms same successful canonical IMAPS transport points at configured
publicmailVIP203.14.220.11; topology already maps it to server10.10.2.25 and core
renders the private destination. Address inequality is not a semantic wrong-host
proof. Do not rewrite the physical tuple or remove the exact binding requirement.

Owner NetworkVisibilityEngine's existing cached static-NAT table: expose read-only
resolve_endpoint_ip, reused by interface selection and the IMAPS guard. The guard
compares the mapped real endpoint to the requested server. Unmapped or unrelated
VIP still rejects before worker/source mutation. Direct-IP behavior, source port,
canonical login interval, public address/canonical UID, missing-source semantics
and token bytes remain unchanged. No PAT allocation, new cache, model/schema or
scenario edits. New native publicmailDNSidentity+static-DNAT case plus pure positive/
unrelated/unmapped tests qualify the non-sample topology sibling. Failure artifacts
retained failed-attempt-1, diagnostic factJSON/logs separate. Bump548for retry,
notreuse547digest; no successful14assessment yet until newbundle/eval/freshpanel.
