#1710774750
ls -ltr
#1710775096
cd -
#1710775475
redis-cli CLIENT LIST | head -5
#1710775485
stat /etc/passwd
#1710775737
grep -i 'session opened' /var/log/auth.log | tail -10
#1710775877
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
