#1710770898
uptime
#1710770994
df -h /
#1710771060
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710771119
find /tmp -maxdepth 1 -type f | head
#1710771363
mount | column -t
#1710778748
iostat -x 1 3
#1710783765
getent passwd $(whoami)
#1710783805
file /usr/bin/ls
