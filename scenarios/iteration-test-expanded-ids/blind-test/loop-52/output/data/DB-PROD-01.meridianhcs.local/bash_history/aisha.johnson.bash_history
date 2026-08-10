#1710763241
yum check-update 2>/dev/null
#1710765664
systemctl is-active mysql
#1710765673
journalctl -u sshd -n 20 --no-pager
#1710766074
ss -ltnp | grep sshd
#1710766319
systemctl cat mysql 2>/dev/null | head -40
#1710766351
vmstat 1 5
#1710776871
iptables -L -n
#1710777020
resolvectl query login.microsoftonline.com
#1710778951
systemctl status mysql --no-pager
#1710779017
journalctl -u mysql --since '30 min ago' --no-pager | tail -100
#1710779734
ps aux | grep mysql
#1710780341
systemctl list-timers
#1710784322
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710784492
systemd-analyze blame | head
