#1710764336
date
#1710764759
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710764851
apt list --upgradable 2>/dev/null
#1710768038
systemctl status dovecot --no-pager
#1710768149
journalctl -u postfix --since '30 min ago' --no-pager | tail -200
#1710768162
ss -ltnp | grep systemd-resolved
#1710768207
systemctl show imaps -p ActiveState -p SubState -p MainPID
#1710768360
clear
#1710772978
systemctl is-active dovecot
#1710773072
journalctl -u postfix --since '30 min ago' --no-pager | tail -50
#1710782321
ls -ltr
#1710782635
uptime
#1710782701
systemctl status NetworkManager --no-pager
