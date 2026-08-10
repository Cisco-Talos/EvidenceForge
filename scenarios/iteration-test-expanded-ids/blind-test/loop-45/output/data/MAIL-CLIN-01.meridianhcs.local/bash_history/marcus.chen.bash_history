#1710777759
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710778335
uptime
#1710778627
uname -sr
#1710778686
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710778815
du -sh /tmp/*
#1710778987
htop
#1710778998
netstat -an | grep ESTABLISHED | wc -l
#1710779026
ls -lt /var/log | head
#1710779075
cd -
#1710779082
top -bn1 | head -20
#1710779166
ls
#1710779235
ps aux --sort=-%mem | head
