#1710783641
systemctl status mysql --no-pager
#1710783914
journalctl -u mysql --since '30 min ago' --no-pager | tail -200
#1710783974
ps aux | grep sshd
#1710784152
systemctl cat mysql 2>/dev/null | head -40
#1710784453
systemd-analyze blame | head
