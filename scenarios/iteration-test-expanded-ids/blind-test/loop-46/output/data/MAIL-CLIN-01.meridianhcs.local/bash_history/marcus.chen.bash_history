#1710767428
last -20
#1710768044
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710768335
grep -i 'session opened' /var/log/auth.log | tail -20
#1710768553
pwd
#1710768635
clear
#1710769689
tail -20 /var/log/syslog
#1710769749
journalctl -u smtp -n 200
#1710769795
journalctl -u systemd-resolved -n 100
#1710769808
ls /tmp
#1710770090
apt list --upgradable 2>/dev/null
#1710770144
loginctl user-status
#1710770166
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710770220
umask
#1710770249
free -h
#1710780545
systemctl status smtp --no-pager
#1710781906
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710781994
ps aux | grep smtp
#1710782048
systemctl cat dovecot 2>/dev/null | head -40
#1710782061
resolvectl query login.microsoftonline.com
