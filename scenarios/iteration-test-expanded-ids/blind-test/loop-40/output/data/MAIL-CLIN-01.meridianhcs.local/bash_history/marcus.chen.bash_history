#1710766548
systemctl is-active smtp
#1710767259
whoami
#1710767359
ls -lah
#1710767407
date
#1710767488
grep -m1 'model name' /proc/cpuinfo
#1710767524
cat /etc/fstab
#1710767588
cat /proc/meminfo | head -5
#1710767910
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710768037
loginctl session-status
#1710768049
grep -i warning /var/log/syslog | tail
#1710768118
dmesg | tail -30
#1710768195
resolvectl status 2>/dev/null | head -30
#1710779627
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710780622
ps aux --sort=-%mem | head
#1710780696
who -a
#1710780871
systemctl list-units --failed
#1710780912
ss -ltnp | grep systemd-resolved
#1710781763
ss -tulnp
