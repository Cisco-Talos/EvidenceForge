# Site-owned HTTP resource identity

Classification: sibling_defect / family_level. Owner: canonical HTTP resource
content identity, shared by size planning and file-transfer identity before render.

Invariant: a resource belongs to its canonical origin host and resource path by
default. Repeated clients/sensors keep the same identity/size. Unrelated sites
sharing a generic favicon/logo path do not inherit one global content-size seed.
Cross-origin shared bytes require an explicit configured content identity, such as
the modeled common Inter font; size and file digest must agree on that ownership.

Entry paths: browser subresources, HTTP response estimation, direct file analysis
and proxy client/origin pairs. Keep entity legality, MIME, transfer-size stability,
cache behavior and explicit content_identity overrides. Test site-owned favicon/
logo/CSS siblings, same-site repeat/query handling, explicit common font and paired
file identity. This is modeled resource ownership, not a demand for arbitrary entropy.

## Second verified family: Windows failed-logon condition

Primary Microsoft4625 documentation defines FailureReason as text for Status and
shows %%2307 with STATUS_ACCOUNT_LOCKED_OUT(0xc0000234). Our disabled-account path
sets generic STATUS_LOGON_FAILURE(0xc000006d), disabled SubStatus(0xc0000072) and
%%2307. The native reason contradicts the main status; eCAR's fallback dictionary
also incorrectly labels2307as disabled, although known substatus currently masks it.

Owner: canonical typed failed-logon condition before AuthContext construction.
Compute status/substatus/native resource token together for known, unknown and
disabled account failures, all through the existing failed-logon action path.
For the existing generic main-status model retain generic2313reason and specific
substatus; do not invent account lockouts or alter account state/SID/RNG/cadence.
Correct the source-native eCAR fallback for2307 while preserving numeric substatus
normalization. Cover disabled/bad-password/unknown siblings and native/eCAR agreement.
Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
