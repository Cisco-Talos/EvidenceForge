#1710768623
whoami
#1710768637
ls -ltr
#1710768683
date
#1710768868
cat /etc/mysql/my.cnf | grep -v '^#'
#1710778442
pg_isready
#1710778682
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710778708
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710778739
du -sh /var/lib/mysql/*
#1710778903
ulimit -n
#1710778938
ps aux --sort=-%mem | head
#1710779209
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW GLOBAL STATUS LIKE "Threads_connected"'
#1710779240
stat /etc/passwd
#1710779300
loginctl list-sessions
#1710779351
last -5
#1710782833
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT NOW(), USER()'
#1710783020
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW PROCESSLIST'
#1710783230
tail -100 /var/log/mysql/error.log
#1710783674
journalctl --since '10 min ago' --no-pager -n 20
#1710783682
psql -c '\l'
#1710783707
ls /tmp
