#1710763272
uptime
#1710763361
lsblk
#1710774562
journalctl --since '10 min ago' --no-pager -n 20
#1710774735
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710775229
env | head -20
#1710775283
systemd-analyze blame | head
#1710775291
who
#1710775448
top -bn1 | head -20
