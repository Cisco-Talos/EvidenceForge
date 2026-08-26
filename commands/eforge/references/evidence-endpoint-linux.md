---
description: "eCAR, Linux syslog, and bash-history evidence reference"
---

# Endpoint And Linux Evidence

Read this reference for simulated EDR/eCAR records, Linux syslog rendering, or bash history.

## eCAR Simulated EDR

Each participating host writes NDJSON to `<host>/ecar.json`. A record has timestamp, ID, hostname,
object, action, persistent `objectID`, optional `actorID`, optional principal, optional nonnegative
top-level `pid`/`tid`/`ppid`, and a `properties` map whose values are strings. Missing source-native
process/thread identities are omitted rather than rendered as negative sentinels.

`objectID` joins an entity lifecycle, such as PROCESS CREATE/TERMINATE or USER_SESSION
LOGIN/LOGOUT. `actorID` links the acting entity, such as a child process to its parent or a file
operation to its owning process.

| Object | Actions | Contract |
| --- | --- | --- |
| PROCESS | CREATE, TERMINATE, OPEN | Process lifecycle and access; correlates with Windows/Sysmon or Linux process/syslog evidence. |
| THREAD | REMOTE_CREATE | Shared remote-thread source/target identity and addresses with Sysmon Event 8. |
| FILE | READ, CREATE, WRITE, RENAME, DELETE | Local process activity, canonical SMB effects, and modeled transfer receiver evidence. |
| FLOW | CONNECT | Host-perspective tuple with process attribution only when known. |
| REGISTRY | MODIFY | Windows registry activity. |
| MODULE | LOAD | Process-aware Windows DLL/module loads. |
| USER_SESSION | LOGIN, LOGOUT | Outcome plus Windows logon type or OS-native session type; failure does not imply a session. |
| SERVICE | CREATE | Service identity, binary path, and account; correlates with Windows 4697. |

eCAR is optional and may not exist on every system. Linux coverage focuses on PROCESS,
USER_SESSION, FLOW, and FILE rather than every endpoint object family. File paths come from
curated OS-aware profiles, not a complete endpoint inventory.

Successful SSH and RDP sessions retain complete terminal ownership: source/receiver processes and the
target session close exactly once; watermarks transfer proof only, and finalization renders the close.

For SMB, keep every actor host-local. Windows-native clients may expose System PID 4, direct
`smbclient` uses its one-shot operation process, mounted CIFS is kernel-owned rather than falsely
owned by `mount.cifs`, and Samba responder FLOW/FILE evidence uses the active `smbd` worker. Samba
FILE rows use POSIX server paths; Linux client-local copy/move effects use POSIX paths and their
local application actor. A Samba USER_SESSION has `session_type: smb`, a neutral auth/session
reference, SMB principal, protocol/scope, and optional effective UID/GID. It never invents Windows
SID, LUID, logon-type, or logon-GUID fields. Do not carry a PID from one host to another.

## Linux Syslog

- Default/Splunk: `<host>/syslog.log`, RFC5424 with full timestamp year.
- SOF-ELK®: `<host>/<year>/syslog.log`, RFC3164/BSD with PRI.

Evaluation recognizes these current variants and compatible legacy flat formats. Each row is a
distinct canonical occurrence. Higher-level bundles coordinate multi-row SSH/session lifecycles,
timing, tuple identity, and source ordering. Failed-password rows reuse the companion Zeek SSH
source port. SSH retirement remains provable after the shared channel tombstone expires, while the
existing lifecycle finalizer remains the sole owner of PAM/logind and endpoint termination rows.

| Activity/program family | Behavior |
| --- | --- |
| `sshd` and PAM | Accepted/failed auth and session lifecycle. |
| `systemd`, `systemd-logind`, `systemd-journald`, `systemd-timesyncd` | Service/timer, session, journal housekeeping, and time activity. |
| `CRON`, `cron`, `anacron` | Distro-aware scheduled jobs and coherent anacron runs. |
| Package maintenance | Distro-/host-aware systemd lifecycle and `unattended-upgr`/PackageKit detail for apt/dnf activity. |
| `logrotate` | Service/timer lifecycle and per-file detail. |
| `kernel` and UFW | Boot/audit and blocked-network evidence. |
| `sudo`, `su`, `polkitd` | Privilege, user-switch, and host-appropriate authorization. |
| Host/role daemons | Network, resolver, logging, snap, firmware, desktop, storage, and service-aware background activity. |
| `smbd` | Samba authentication, effective identity, share connect, and disconnect. |
| `smbd_audit` | Profile-gated VFS operation/result with the POSIX server path. |

Samba uses this destination-host-local text syslog family, not a new output format. `minimal`
records connect/authenticate/disconnect, `standard` adds selected VFS operations, and `high` adds
configured full-audit successes and failures. Per-file rows remain configuration-dependent because
upstream `vfs_full_audit` has no default success/failure operation set. Routine successful CIFS or
`smbclient` use has no universal client syslog; do not fabricate PAM sessions, kernel CIFS debug,
Linux Audit, or client per-file syslog. Audit operation defaults are version-sensitive; consult
Samba's [`smb.conf`](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) and
[`vfs_full_audit`](https://www.samba.org/samba/docs/current/man-html/vfs_full_audit.8.html)
contracts.

Program/message coverage is curated and role/distro-aware rather than a complete journal.
Application-specific nginx, postfix, or database logs are not implied merely by declaring a
service. Modeled Samba evidence is the explicit exception. The model does not reproduce the entire
SSH protocol negotiation transcript.

## Bash History

`<host>/bash_history/<username>.bash_history` uses timestamped history pairs:

```text
#<epoch>
<command>
```

Baseline SSH sessions generate role-appropriate administration commands. Storyline processes can
interleave a small amount of organic command noise. The Linux shell-command bundle aligns command
text, visible time, and optional foreground-process evidence. Exact two-token numeric sleeps such
as `sleep 30`, `sleep 30.5`, and `sleep .5` model their requested lifetime up to 86,400 seconds;
unsupported forms keep the short fallback, and bounded sessions preserve a 1,425 ms release margin.
History omits output, errors, completion artifacts, and realistic typo/retry behavior, and may be
sparse relative to a long SSH session.
