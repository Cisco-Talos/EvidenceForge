#1710780049
du -sh /var/log/*
#1710781409
stat /etc/passwd
#1710781418
free -m
#1710781474
hostname -f
#1710781681
resolvectl status 2>/dev/null | head -30
#1710781740
ls -la
#1710781794
find /tmp -maxdepth 1 -type f | head
#1710781845
groups
#1710781856
date
#1710782188
greo
#1710782416
ulimit -n
#1710784259
journalctl -u php-fpm --since '30 min ago' --no-pager | tail -20
