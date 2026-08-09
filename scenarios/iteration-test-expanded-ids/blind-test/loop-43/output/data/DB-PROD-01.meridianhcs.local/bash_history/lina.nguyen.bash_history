#1710771193
pg_isready
#1710771214
psql -c 'SELECT count(*) FROM pg_stat_activity'
#1710771237
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710771262
du -sh /var/lib/mysql/*
#1710771562
cd -
#1710771788
cat /etc/issue
#1710771856
lsmod | head
#1710771878
getent passwd $(whoami)
#1710771905
dmesg --ctime | tail -20
#1710772229
ls /var/log
