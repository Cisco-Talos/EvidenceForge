#1710781742
grep -i error /var/log/syslog | tail -100
#1710781889
systemd-analyze blame | head
#1710781948
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710782008
du -sh /home/* 2>/dev/null | head
#1710782065
w
#1710782378
find /var/log -name '*.gz' -mtime +30 | wc -l
