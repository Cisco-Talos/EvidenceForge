#1710768459
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710768481
mysqldump --single-transaction --routines mydb > /tmp/production_backup.sql
#1710768540
grep -i failed /var/log/auth.log | tail
#1710768922
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW SLAVE STATUS\G'
#1710783033
getent hosts localhost
#1710783059
ls
#1710783469
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710783493
grep -i warning /var/log/syslog | tail
#1710783548
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Threads_connected"'
#1710783563
psql -c 'SELECT schemaname, relname FROM pg_stat_user_tables LIMIT 10'
