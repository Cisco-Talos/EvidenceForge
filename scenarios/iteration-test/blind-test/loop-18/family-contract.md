# Canonical NTLM credential validation and mechanism-owned identity — draft

Finding16Detection:114/121domain NTLM Type3 successes lack any successful4776 pair;
108nonzeroGUID cases allunmatched. Engineering probe independently reproduces exact
counts. Export filtering remains a raw-data alternative, but source audit confirms
persistent Windows SMB directly builds logon/source cohort and bypasses validation;
generic helper blanket-skips DC target (6zero-GUID missing remote DC logons).

Owners: shared authentication planning/factory and persistent SMB canonical source
cohort; State session creation owns native LogonGuid availability. Add a shared
pure authority/phase planner returning the existing canonical validation intent,
not a renderer callback. Persistent source drafts must carry it through existing
prepared cohort publication/recovery. Generic remote logon adapts into the same
owner. No fresh network connection is implied per validation: Netlogon may use an
existing channel; don't fabricate wire rows.

Invariant: selected NTLM success with modeled authoritative credentials builds a
credential validation occurrence on that authority before authentication, subject
to normal source observation. Domain authority is a modeled DC, including target
DC for REMOTEType3; local Windows authority is the target. Original client supplies
Workstation. Kerberos, well-known/anonymous, cached/local-interactive, separately
owned machine validation and genuinely unknown/unmodeled authority remain distinct.
Explicit failed validation still uses its failure status. Do not add success rows
to failed credentials or count ACL denial as credential failure.

Protocol selection stays authoritative; do not switch NTLM to Kerberos to erase
the finding. The public typed SMB protocol is ntlmssp; persistent Windows auto currently
uses an internal ntlm fallback. Recognize both concrete internal spellings in
shared planning without changing the public authored schema. Domain-backed Samba member NTLM is a sibling;
standalone/local Samba must not invent an ADvalidation. Resolve account scope via
canonical IdentityDirectory and existing principal/SID facts, not a SID-prefix
assumption alone. No new authority cache or arbitrary per-auth DC flip-flopping.

PersistentSmbRootIntent currently calls plan_session(logon_guid_required=True)
regardless of mechanism. Set availability from resolved mechanism at that owner;
all downstream AuthContexts use the same State identity. NTLM's common uncaptured
GUID is zero; nonzero NTLM is not declared universally impossible. Preserve native
Kerberos GUIDs, LUID/object IDs, Type9/RDP and checkpoint identity contracts.

Inventory: persistent Windows SMB initial/direct/composite/auto paths, generic
Windows remote logon, DC target, Samba AD member and standalone/local, failed logon,
manual NtlmValidationRequest/ActionBundle, machine account, Kerberos/DC bundle,
causal expansion, renderer normal/exact and source observation. New audit should
fit existing spare source overhead after exact member/byte/row accounting proof;
no blind ceiling growth or source drop forcing. Canonical validation phase uses
TimingRuntime/named data timing profile and same physical transport bounds.

Consumers: Windows4776/4624/4634, Samba auth/eCAR session views, observation clocks,
SMB prepared snapshots/receipt source groups, fault/exact recovery and checkpoints.
No authored scenario or reviewer instruction changes. No18engine edits while17
retry552andpost active.

Primary evidence:
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
4776documents NTLM validation at authoritative computer, original client Workstation,
and distinguishes domain-local logon on DC from remote network logon.
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
GUID may be uncaptured/zero. Do not infer source-native impossibility from nonzero
NTLM alone. No reviewer guidance is changed to point at this family.

Read-only refinement: _build_dc_host_context fabricates WindowsServer2019/DC facts
from a hostname string and cannot represent local authority truth. Shared canonical
validation draft construction should use actual modeled authority System/HostContext,
preserving legacy explicit unmodeled-DC fallback only for the manual request path.
Initial native-before fixture used unsupported public auth_protocol:ntlm, so those
3schema failures are not behavior proof. Corrected to documented ntlmssp and rerun.
No18source edits while17retry552/post active.

Qualified native-before evidence: all three NTLMSSP public-entry cases (DC target,
Windows member, Samba member) fail specifically on zero successful validations,
not schema. First unsupported-alias fixture failures remain separate evidence.
Loop17 retry and its evaluation/probes/neutral preparation have now exited0.

Corrected exact capacity accounting: source drafts have4+3N+client members PLUS
one separately prepared tree-disconnect =>5+3N+client, fully consuming the old
reservation. A canonical validation requires precisely one additional member,
its authenticated capsule and ordinary per-member row/byte accounting. Add that
member only for known NTLM authority; structural maximum becomes7+3*max_operations
from6+3*max_operations (one client plus the new audit), with no operation-count,
manager admission, temporal RNG census or retention ceiling increase. Add a distinct
credential_validation phase so the retained proof is not mislabeled as file data.
The exact new source must travel in the existing prepared/recovery graph; never
redispatch it after commit. This is necessary evidence provisioning, not making
an unrelated failure pass by relaxing its guard.

The shared canonical planner/factory is housed with existing authentication bundle
execution in ActivityGenerator. Persistent and generic callers adapt to it; it
returns a draft rather than dispatching so transactional callers retain ownership.
Manual validation uses the same builder with existing explicit failure/success.
Legacy direct generators lacking IdentityDirectory have no automatic scope proof;
manual API remains. Existing owned machine-bundle validation stays independent.
