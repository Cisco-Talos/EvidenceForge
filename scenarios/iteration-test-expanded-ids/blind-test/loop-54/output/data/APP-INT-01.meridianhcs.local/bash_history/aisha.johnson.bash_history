#1710763915
systemctl is-active sshd
#1710763925
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -50
#1710763961
ss -ltnp | grep sshd
#1710775038
systemctl status systemd-resolved --no-pager
#1710775117
journalctl -u systemd-resolved -n 20 --no-pager
#1710775174
ps aux | grep systemd-resolved
#1710775260
systemctl cat systemd-resolved 2>/dev/null | head -40
