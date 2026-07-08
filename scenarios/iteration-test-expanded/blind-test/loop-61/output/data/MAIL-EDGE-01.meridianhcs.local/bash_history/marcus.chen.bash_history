#1710765158
last -20
#1710765180
tail -200 /var/log/auth.log
#1710765519
grep -i 'failed password' /var/log/auth.log | tail -20
#1710765787
tail -f /var/log/syslog &
#1710765793
ls
#1710766205
ss -s
#1710766277
lsmod | head
#1710766465
ps -ef
#1710772056
hostname -f
#1710772087
ls -ltr
#1710772118
uptime
#1710772310
jouranlctl
#1710773140
timedatectl
#1710773990
du -sh /var/log/*
#1710776044
systemctl status smtp --no-pager
#1710776237
journalctl -u dovecot --since '30 min ago' --no-pager | tail -50
#1710776334
ps aux | grep dovecot
#1710776426
systemctl cat dovecot 2>/dev/null | head -40
#1710776494
cat /etc/resolv.conf
#1710777240
history | tail -15
#1710777290
getent passwd $(whoami)
#1710777536
tail -f /var/log/syslog &
#1710777572
getent hosts localhost
#1710779958
systemctl is-active dovecot
#1710780021
journalctl -u dovecot -n 200 --no-pager
#1710780034
ps aux | grep smtp
#1710780114
systemctl cat imaps 2>/dev/null | head -40
#1710780247
who
#1710780376
ip route get 8.8.8.8
#1710780561
lsmod | head
#1710780769
cd ~
#1710780838
iostat -x 1 3
#1710781224
iptables -L -n
#1710782368
ls -lh
#1710782460
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710782542
ls -lah /tmp | head
#1710782658
tail -20 ~/.bash_history
#1710782765
free -h
#1710783143
journalctl -u systemd-resolved -n 100
#1710783227
journalctl --no-pager -n 5
#1710783275
cat /proc/meminfo | head -5
#1710783539
uptime
#1710783609
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710783644
systemctl --failed --no-pager
