#1710767235
uptime
#1710767626
df -h /
#1710767720
systemctl --failed --no-pager
#1710767748
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710774930
locale
#1710774997
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710775164
find /var/log -name '*.gz' -mtime +30 | wc -l
