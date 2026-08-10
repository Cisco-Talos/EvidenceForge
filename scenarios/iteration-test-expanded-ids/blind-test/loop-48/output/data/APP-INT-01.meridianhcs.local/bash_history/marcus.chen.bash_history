#1710767466
hostnamectl
#1710767555
free -h
#1710767588
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710767623
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710767705
grep -m1 'model name' /proc/cpuinfo
#1710767775
systemctl restart gunicorn
#1710767914
systemctl list-units --failed
#1710767924
ip route get 8.8.8.8
#1710768322
grep -i failed /var/log/auth.log | tail
#1710768438
who
#1710780996
date -u
#1710781007
cat /proc/cpuinfo | grep 'model name' | head -1
#1710781380
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710781441
grep -i warning /var/log/syslog | tail
#1710781844
loginctl user-status
