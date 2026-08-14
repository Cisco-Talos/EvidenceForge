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

## Linux Syslog

- Default/Splunk: `<host>/syslog.log`, RFC5424 with full timestamp year.
- SOF-ELK®: `<host>/<year>/syslog.log`, RFC3164/BSD with PRI.

Evaluation recognizes these current variants and compatible legacy flat formats. Each row is a
distinct canonical occurrence. Higher-level bundles coordinate multi-row SSH/session lifecycles,
timing, tuple identity, and source ordering. Failed-password rows reuse the companion Zeek SSH
source port.

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

Program/message coverage is curated and role/distro-aware rather than a complete journal.
Application-specific nginx, postfix, or database logs are not implied merely by declaring a
service. The model does not reproduce the entire SSH protocol negotiation transcript.

## Bash History

`<host>/bash_history/<username>.bash_history` uses timestamped history pairs:

```text
#<epoch>
<command>
```

Baseline SSH sessions generate role-appropriate administration commands. Storyline processes can
interleave a small amount of organic command noise. The Linux shell-command bundle aligns command
text, visible time, and optional foreground-process evidence. History does not include command
output, error text, tab-completion artifacts, or realistic typo/retry behavior, and may be sparse
relative to a long SSH session.
