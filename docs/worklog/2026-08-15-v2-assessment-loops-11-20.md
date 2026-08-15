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

