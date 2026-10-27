# Northstar Software environment

Northstar Software is a small software consultancy with three modeled staff and
four systems. Maya Chen and Owen Patel are developers using Apple Silicon Macs;
Nora Ellis handles operations from Windows. The Ubuntu build server also hosts the
Engineering Samba share. Accounts are scenario-local; no Active Directory domain
controller is modeled.

| Host | Address | Platform | Role |
| --- | --- | --- | --- |
| NS-BUILD-01 | 10.42.0.31 | Ubuntu 24.04 x64 | Build, SSH and Samba services |
| NS-MAC-01 | 10.42.0.11 | macOS 27, modeled build, arm64 | Maya Chen's workstation, SMB client |
| NS-MAC-02 | 10.42.0.12 | macOS 27, modeled build, arm64 | Owen Patel's workstation, SSH and SMB client |
| NS-WIN-01 | 10.42.0.21 | Windows 11 x64 | Nora Ellis's operations workstation |

Usernames are `maya.chen`, `owen.patel` and `nora.ellis`, with corresponding email
addresses at `northstar.example`. All belong to Engineering. The Engineering share
is backed by `/srv/samba/engineering` and available through modeled persistent Mac
mounts. Workstations and server occupy `10.42.0.0/24`; an office SPAN observes both
directions. Firewall, proxy and mail collectors are absent.

The main UTC window is 2026-10-20 13:00–19:00, with warmup from 12:00 UTC. Local
scheduling uses America/New_York (UTC−04:00 on this date), so the main window is
09:00–15:00 local. Emitted evidence timestamps use UTC.

Available evidence is normalized eCAR endpoint telemetry, Zeek network records,
Windows event records, Linux syslog, Bash and zsh histories, selected macOS Unified
Log callsites, and a bounded macOS 27 arm64 Endpoint Security/eslogger export using
message version 11. Complete fork/exec/known-exit facts may be emitted; unknown
metadata does not acquire placeholder fields. Local GUI audit origin is modeled,
while GUI launch responsibility and comprehensive app-launch logging are outside
this collection profile. Selected Unified Log callsites include workspace entry
and explicit app-policy refusal; neither source is a comprehensive Mac audit trail.
Native file/auth ES families, full helper/PTY descriptor coverage, populated
entitlements, native Mac SSH/SMB logs and filesystem acquisition are not collected.
