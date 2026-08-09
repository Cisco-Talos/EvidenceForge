#1710770105
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Uptime"'
#1710770132
du -sh /var/lib/mysql/*
#1710770167
mysqldump --single-transaction --routines production > /tmp/appdb_backup.sql
#1710783951
du -sh /var/log
#1710784245
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710784374
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW PROCESSLIST'
#1710784391
w
#1710784551
du -sh /home/* 2>/dev/null | head
