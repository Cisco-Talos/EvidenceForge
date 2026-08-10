#1710763229
lsblk
#1710778659
systemctl status systemd-resolved --no-pager
#1710778693
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -200
#1710779918
ps aux | grep sshd
