#1710766769
pwd
#1710769140
du -sh /tmp/*
#1710769161
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710769174
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710769234
ls /var/log
#1710772842
hostname -f
#1710772903
grep -i error /var/log/syslog | tail
#1710773043
env | head -20
#1710773073
ss -s
#1710773110
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710774896
nmcli connection show --active
#1710775275
iptables -L -n
#1710775309
systemctl list-timers
#1710775661
cat /etc/issue
#1710775752
htop
#1710780083
crontab -l
#1710780155
ls -la
#1710780235
cat /proc/sys/kernel/osrelease
#1710780307
cat /etc/os-release
#1710780362
resolvectl query login.microsoftonline.com
