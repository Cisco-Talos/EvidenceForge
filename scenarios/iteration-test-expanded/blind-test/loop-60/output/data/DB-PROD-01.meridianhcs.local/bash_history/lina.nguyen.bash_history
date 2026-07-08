#1710764534
hostnamectl
#1710764699
df -h /
#1710764810
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710764979
cat /etc/mysql/my.cnf | grep -v '^#'
#1710765135
du -sh /var/log
#1710765172
grep -m1 'model name' /proc/cpuinfo
#1710765209
psql -c '\dt'
