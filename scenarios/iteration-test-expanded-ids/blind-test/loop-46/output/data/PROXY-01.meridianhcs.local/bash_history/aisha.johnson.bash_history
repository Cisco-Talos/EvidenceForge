#1710767821
last -5
#1710771317
grep -i error /var/log/syslog | tail
#1710779220
lsblk
#1710779310
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710779404
history | tail -15
#1710779416
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710779475
systemctl status squid
#1710784060
id
#1710784152
grep -i failed /var/log/auth.log | tail
#1710784184
du -sh /home/* 2>/dev/null | head
