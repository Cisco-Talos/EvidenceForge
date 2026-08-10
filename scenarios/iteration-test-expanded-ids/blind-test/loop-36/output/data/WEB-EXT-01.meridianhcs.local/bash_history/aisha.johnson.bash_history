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
#1710777504
last -20
#1710777512
systemctl is-active php-fpm
#1710777594
journalctl -u php-fpm -n 50 --no-pager
