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
#1710783179
journalctl -u systemd-resolved --since today --no-pager | tail -20
