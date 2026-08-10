#1710768045
who -a
#1710768340
tail -200 /var/log/auth.log
#1710775566
systemctl status mysql --no-pager
#1710776131
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710776217
ss -ltnp | grep mysql
#1710776282
systemctl cat mysql 2>/dev/null | head -40
