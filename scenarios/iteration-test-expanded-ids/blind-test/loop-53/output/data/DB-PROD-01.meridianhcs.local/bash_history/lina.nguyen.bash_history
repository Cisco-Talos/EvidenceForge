#1710772790
pg_isready
#1710772838
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710772868
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Threads_connected"'
#1710772893
du -sh /var/lib/mysql/*
#1710773085
pt-query-digest /var/log/mysql/slow.log | head -50
