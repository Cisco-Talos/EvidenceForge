#1710765745
timedatectl
#1710766112
free -h
#1710766133
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710766374
journalctl --since '10 min ago' --no-pager -n 20
#1710778603
id
#1710778778
du -sh /tmp/*
#1710778789
cat /proc/version | cut -d' ' -f1-3
#1710778836
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
