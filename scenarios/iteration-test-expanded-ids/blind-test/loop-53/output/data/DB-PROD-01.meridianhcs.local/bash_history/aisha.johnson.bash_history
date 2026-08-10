#1710763241
yum check-update 2>/dev/null
#1710765629
last -20
#1710765655
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710765821
grep -i 'session opened' /var/log/auth.log | tail -20
#1710780219
tail -20 /var/log/auth.log
#1710780318
journalctl -u mysql --since '30 min ago' --no-pager | tail -20
