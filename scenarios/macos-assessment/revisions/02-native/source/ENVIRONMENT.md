# Northstar Software environment

Northstar Software is a small software consultancy with three modeled staff and
four systems. Maya Chen and Owen Patel are developers using Apple Silicon Macs;
Nora Ellis handles operations from Windows. The Ubuntu build server also hosts the
Engineering Samba share. Accounts are scenario-local; no Active Directory domain
controller is modeled.

| Host | Address | Platform | Role |
| --- | --- | --- | --- |
| NS-BUILD-01 | 10.42.0.31 | Ubuntu 24.04 x64 | Build, SSH and Samba services |
| NS-MAC-01 | 10.42.0.11 | macOS 26, 25A354, arm64 | Maya Chen's workstation, SMB client |
| NS-MAC-02 | 10.42.0.12 | macOS 26, 25A354, arm64 | Owen Patel's workstation, SSH and SMB client |
| NS-WIN-01 | 10.42.0.21 | Windows 11 x64 | Nora Ellis's operations workstation |

Usernames are `maya.chen`, `owen.patel` and `nora.ellis`, with corresponding email
addresses at `northstar.example`. All belong to Engineering. The Engineering share
is backed by `/srv/samba/engineering` and available through modeled persistent Mac
mounts. Workstations and server occupy `10.42.0.0/24`; an office SPAN observes both
directions. Firewall, proxy and mail collectors are absent.

The main UTC window is 2026-10-20 13:00–19:00, with warmup from 12:00 UTC. Local
scheduling uses America/New_York (UTC−04:00 on this date), so the main window is
09:00–15:00 local. Emitted evidence timestamps use UTC.

Available evidence is eCAR endpoint telemetry, Zeek network records, Windows event
records, Linux syslog, Bash and zsh histories, and a bounded macOS Unified Log
workspace-entry export. A bounded modeled Endpoint Security export selects macOS 26
arm64 fork notifications (message version 10) for eligible canonical forks. Ordinary
process launches do not assert a fork. Native ES exec/exit and policy-denial exports
are unavailable. Windows and Linux sources belong to their respective hosts. The
Unified Log selection is partial and does not provide a comprehensive Mac audit
trail. Native Mac SSH/SMB logs, native Gatekeeper decisions and filesystem artifact
acquisition are not collected.
