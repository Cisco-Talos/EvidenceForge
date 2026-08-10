#1710771889
tail -50 /var/log/auth.log
#1710771946
systemctl restart squid
#1710772011
ls -la
#1710772092
tail -200 /var/log/syslog
#1710772438
cd -
#1710772460
ls -ld /var/log
#1710772741
resolvectl status 2>/dev/null | head -30
#1710772900
grep -i error /var/log/syslog | tail -20
#1710772908
netstat -an | grep ESTABLISHED | wc -l
