#1710772228
systemctl is-active sshd
#1710772403
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710772607
ps aux | grep squid
#1710772815
systemctl cat sshd 2>/dev/null | head -40
#1710772855
cat /proc/version | cut -d' ' -f1-3
#1710773296
loginctl session-status
#1710773323
ss -tulnp
#1710773332
df -h /tmp
#1710773418
ps -ef
#1710773442
ls -ld /var/log
#1710773464
df -h
#1710773533
ls -ltr /var/log | tail
#1710773843
ulimit -n
#1710773887
journalctl -u sshd --since '1 hour ago'
#1710773920
cd /var/log
#1710773981
pwd
#1710773995
free -m
#1710774052
loginctl list-sessions
#1710776267
tail -f /var/log/syslog &
#1710776675
systemctl list-timers
#1710776766
file /usr/bin/ls
#1710776861
hostnamectl
#1710776910
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710777129
stat /etc/passwd
#1710777551
clear
#1710777598
grep -i 'failed password' /var/log/auth.log | wc -l
#1710779794
systemctl is-active systemd-resolved
#1710779975
journalctl -u squid --since '30 min ago' --no-pager | tail -50
#1710780046
ss -ltnp | grep squid
#1710780139
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710780151
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710780271
getent hosts localhost
#1710780337
htop
#1710780388
grep -i failed /var/log/auth.log | tail
#1710780455
vmstat 1 5
#1710780463
cat /proc/version | cut -d' ' -f1-3
#1710780705
ps -ef
#1710780798
journalctl -u sshd --since '1 hour ago'
#1710780979
command -v python3
#1710781353
last -20
#1710781714
tail -20 /var/log/auth.log
#1710781754
grep -i 'failed password' /var/log/auth.log | tail -20
#1710781767
loginctl user-status
#1710781826
who
#1710781907
cat /proc/sys/kernel/osrelease
#1710782187
apt list --upgradable 2>/dev/null
#1710782244
resolvectl query company.okta.com
#1710782312
tail -20 /var/log/syslog
