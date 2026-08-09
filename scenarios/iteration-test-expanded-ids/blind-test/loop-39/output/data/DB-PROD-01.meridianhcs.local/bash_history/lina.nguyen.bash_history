#1710770105
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Uptime"'
#1710770132
du -sh /var/lib/mysql/*
#1710770167
mysqldump --single-transaction --routines production > /tmp/appdb_backup.sql
#1710775410
systemd-analyze blame | head
#1710775626
cat /etc/hostname
#1710775873
env | sort | head
#1710775977
resolvectl status 2>/dev/null | head -30
#1710776378
tail -200 /var/log/mysql/error.log
#1710776731
journalctl -p err --no-pager -n 10
#1710777041
du -sh /home/* 2>/dev/null | head
#1710777138
cd /var/log
