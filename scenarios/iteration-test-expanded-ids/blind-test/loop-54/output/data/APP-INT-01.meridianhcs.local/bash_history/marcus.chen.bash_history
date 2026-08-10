#1710780429
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710780517
systemctl list-units --failed
#1710780663
netstat -an | grep ESTABLISHED | wc -l
#1710780771
journalctl -p err --no-pager -n 10
#1710781104
umask
#1710781113
iostat -x 1 3
#1710781169
grep -i 'session opened' /var/log/auth.log | tail -10
#1710781178
cat /proc/meminfo | head -5
#1710781225
journalctl -u gunicorn -n 200
#1710783084
date -u
#1710784049
cd /var/log
#1710784190
file /usr/bin/ls
#1710784200
grep -i warning /var/log/syslog | tail
#1710784371
journalctl -u gunicorn --since '30 min ago' --no-pager | tail -20
#1710784396
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
