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
