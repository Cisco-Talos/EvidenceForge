#1710765251
umask
#1710765576
ip -br addr
#1710765657
uptime
#1710765710
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710765913
ls -la /var/lib/mysql/
#1710772890
systemctl --failed --no-pager
#1710773057
journalctl -xe --no-pager | tail -20
#1710773136
psql -c '\l'
#1710773184
redis-cli INFO stats | head -20
#1710773192
history | tail -15
