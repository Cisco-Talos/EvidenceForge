#1710771868
journalctl -u sshd --since '1 hour ago'
#1710771902
df -h
#1710772368
ps aux
#1710772445
ls -ltr /var/log | tail
#1710772493
cat /etc/resolv.conf
#1710776317
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710776642
grep -i 'session opened' /var/log/auth.log | tail -20
#1710776672
df -h /tmp
#1710783991
netstat -an | grep ESTABLISHED | wc -l
#1710784039
iptables -L -n
#1710784483
pwd
