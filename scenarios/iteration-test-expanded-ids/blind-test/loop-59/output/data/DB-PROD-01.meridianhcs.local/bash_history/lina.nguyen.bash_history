#1710764694
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT NOW(), USER()'
#1710765192
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710765214
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Threads_connected"'
#1710765242
du -sh /var/lib/mysql/*
#1710765293
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW PROCESSLIST'
#1710765316
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW VARIABLES LIKE "max_connections"'
#1710765555
psql -c 'SELECT now(), current_user'
#1710765578
mysqldump --single-transaction --routines appdb > /tmp/wordpress_backup.sql
#1710765712
mysqldump --single-transaction --routines mydb > /tmp/appdb_backup.sql
#1710765767
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLE STATUS FROM mydb LIMIT 5'
#1710775513
locale
#1710775817
grep -i error /var/log/syslog | tail
#1710775868
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLE STATUS FROM wordpress LIMIT 5'
#1710775898
env | sort | head
#1710776239
cat /etc/issue
#1710776425
cat /proc/cpuinfo | grep 'model name' | head -1
#1710783372
psql -c 'SELECT pg_size_pretty(pg_database_size(current_database()))'
#1710783843
find /tmp -maxdepth 1 -type f | head
#1710784245
grep -i 'session opened' /var/log/auth.log | tail -10
#1710784290
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710784309
cat /etc/mysql/my.cnf | grep -v '^#'
