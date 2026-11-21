# HTTP command intent and explicit-proxy socket ownership

Finding classification: new_family / contract_gap, panel 5 Threat and all four
actual deliberators. Original Windows/Linux downloader writes a file while a
fabricated curl helper owns the inspected request and advertises a root URL.

Owner: shared command HTTP intent helpers and canonical explicit-proxy client
process attribution/materialization. Exact equality against a generic fallback
command is not an ownership contract for an already running downloader.

Invariant: a live caller in its valid session may own a request when its literal
CLI destination, effective port, path/query and non-body method agree with known
request intent. Output flags do not change the network actor. Proxy/referer/header
URLs are not destinations. Wrong host/port/path/method and expired callers must
not gain ownership. CONNECT-only observations constrain authority, not an
unobserved path. Preserve existing explicit multipart/body ownership and browser,
package/service attribution behavior. Helpers must name the known actual target
resource rather than replacing it with '/'. No argv rewriting or emitter patch.

Entry inventory: process-derived ambient connections, typed storyline downloads,
explicit HTTP/proxy actions, baseline user/service requests, multipart upload,
nested CONNECT transport. Raw supplied evidence remains explicit. Consumers:
canonical process/network/file context, Windows Sysmon/WFP, eCAR, proxy access,
Zeek HTTP/conn/TLS and cross-source lifecycle/evaluation receipts.

Layer rationale: all affected sources agree on an incorrectly substituted PID;
fixing renderers would hide the canonical actor split. Shared parsing fixes the
same proxy-URL-as-target error in process-derived HTTP metadata. Caller and helper
adapters route into this truth. Scope is literal curl/wget non-body intent plus
existing multipart contract; arbitrary shell/Python/PowerShell program semantics
are not inferred from one URL. Unknown arguments/config remain conservative.

Sibling risks: preserve case-sensitive curl -I versus -i, URI query/case, quoted
Windows paths, proxy before destination, --url, methods, unavailable/expired caller,
CONNECT privacy, package/browser resident processes and native file/socket joins.
Focused central unit, actual proxy integration, existing multipart/HTTP-file and
native observation tests precede generation. Verify rendered two-OS actor ownership.

## Sibling regression discovered during focused validation

Existing failed-CONNECT native protocol test fails on unmodified behavior539 too
(status502/503 reset origin): the proxy's transport-only gateway attempt inherits
success-request application byte budgets, so the new generic reset-progress path
correctly interprets the incorrectly supplied bidirectional bytes as an exchange.
Classification exact_regression (behavior538). Owner proxy phase adapter into
canonical network bundle: transport-only failures must pass zero application
payload, no asserted application service/contexts, and suppress inferred app side
effects. Retain failed TCP attempt/close and client CONNECT error body. Do not
revert protocol support on legitimate reset/half-close exchanges. Verify 403/407/
502/503/504, RSTO/RSTR/REJ/S0, plaintext/HTTPS, client upload evidence and successful
exchange siblings. Existing pre-fix failure retained in prototype-tests.log; isolated
unmodified-production reproduction failed identically (1 failed, 1.87 sec).
