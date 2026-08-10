#1710772851
ss -s
#1710773092
systemctl --failed --no-pager
#1710773365
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710773687
cat /etc/passwd | head
#1710773696
systemctl status postfix
#1710778177
free -h
#1710778187
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710778724
getent hosts localhost
#1710778777
cd -
#1710778801
mount | column -t
#1710778842
ls -ld /var/log
#1710779243
cat /proc/version | cut -d' ' -f1-3
#1710779288
systemctl status dovecot
#1710779612
ulimit -n
#1710779721
nmcli device status 2>/dev/null
#1710779771
ss -tan | head
#1710779852
journalctl -u dovecot -n 50
#1710780231
cat /etc/hosts
#1710780297
stat /etc/passwd
#1710780307
htop
#1710782964
tail -20 /var/log/auth.log
#1710782989
grep -i 'session opened' /var/log/auth.log | tail -20
#1710783048
ps -ef
#1710784439
cat /etc/issue
#1710784489
cat /proc/sys/kernel/osrelease
