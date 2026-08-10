#1710765282
systemctl status mysql --no-pager
#1710765300
journalctl -u sshd --since '30 min ago' --no-pager | tail -50
#1710765328
ps aux | grep mysql
#1710765458
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710765625
systemctl --failed --no-pager
#1710765827
hostnamectl
#1710765893
netstat -an | grep ESTABLISHED | wc -l
#1710766277
tail -f /var/log/syslog &
#1710777074
systemctl status sshd --no-pager
#1710777384
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
#1710777579
ps aux | grep sshd
#1710777657
systemctl cat mysql 2>/dev/null | head -40
