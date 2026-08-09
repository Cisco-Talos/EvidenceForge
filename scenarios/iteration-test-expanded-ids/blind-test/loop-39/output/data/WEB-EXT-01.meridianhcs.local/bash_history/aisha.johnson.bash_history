#1710764191
apt list --upgradable 2>/dev/null
#1710764248
free -m
#1710764299
dmesg | tail -30
#1710764393
free -m
#1710764402
uname -a
#1710777074
systemctl status apache2 --no-pager
#1710777096
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -50
#1710777160
ss -ltnp | grep php-fpm
#1710777198
ss -s
#1710777209
tail -200 /var/log/syslog
#1710777605
du -sh /var/log/*
#1710779023
ip route get 8.8.8.8
#1710779158
resolvectl status 2>/dev/null | head -30
#1710779583
top -bn1 | head -20
#1710779859
find /tmp -maxdepth 1 -type f | head
#1710779868
who
#1710779931
tail -20 /var/log/auth.log
