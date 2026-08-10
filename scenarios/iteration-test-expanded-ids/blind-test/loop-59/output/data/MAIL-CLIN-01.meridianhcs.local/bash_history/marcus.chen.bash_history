#1710763307
grep -i 'session opened' /var/log/auth.log | tail -20
#1710763379
nmcli device status 2>/dev/null
#1710763524
clear
#1710765222
uptime
#1710765574
free -h
#1710765669
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710766047
grep -i error /var/log/syslog | tail -20
#1710766079
apt list --upgradable 2>/dev/null
#1710766129
journalctl --no-pager -n 5
#1710766213
tail -f /var/log/syslog &
#1710766310
cd ~
#1710766547
cat /etc/resolv.conf
#1710766557
resolvectl query login.microsoftonline.com
#1710766580
loginctl user-status
#1710771786
mount | column -t
#1710772958
last -20
#1710773030
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710773330
crontab -l
#1710773400
w
#1710773432
umask
#1710773445
free -m
#1710773517
ll
#1710773542
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710773578
ss -s
#1710773929
ip route
#1710773963
cat /etc/os-release
#1710774043
systemctl list-units --failed
#1710774056
tail -100 /var/log/auth.log
