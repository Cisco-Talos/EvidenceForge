#1710771261
hostname -f
#1710771427
ls -ltr
#1710771534
history | tail -15
#1710771917
psql -c '\dt'
#1710774314
ls
#1710774453
cat /proc/cpuinfo | grep 'model name' | head -1
#1710779912
ls -lah
#1710779998
date
#1710780137
psql -c 'SELECT now(), current_database(), current_user'
#1710780322
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710783632
df -h /tmp
