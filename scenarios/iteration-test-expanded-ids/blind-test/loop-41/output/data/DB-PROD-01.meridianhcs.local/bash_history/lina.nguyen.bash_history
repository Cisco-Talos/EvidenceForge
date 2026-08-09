#1710765129
grep -i failed /var/log/auth.log | tail
#1710765733
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLE STATUS FROM analytics LIMIT 5'
#1710765760
grep -i 'session opened' /var/log/auth.log | tail -10
#1710766335
getent hosts localhost
#1710766357
psql -c 'SELECT now(), current_user'
#1710772425
timedatectl
#1710772552
df -h /
#1710772718
systemctl --failed --no-pager
#1710772964
cat /etc/os-release
#1710773050
psql -c 'SELECT schemaname, relname FROM pg_stat_user_tables LIMIT 10'
#1710773079
resolvectl status 2>/dev/null | head -30
#1710773181
cd /var/log
