#1710769606
last -20
#1710769693
tail -50 /var/log/auth.log
#1710769774
grep -i 'session opened' /var/log/auth.log | tail -20
#1710769870
cat /proc/sys/kernel/osrelease
#1710769939
hostnamectl
#1710772346
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710772531
journalctl -xe --no-pager | tail -20
#1710772619
cat /proc/cpuinfo | grep 'model name' | head -1
#1710774818
systemctl is-active mysql
#1710774854
journalctl -u mysql -n 200 --no-pager
#1710775215
ps aux | grep mysql
