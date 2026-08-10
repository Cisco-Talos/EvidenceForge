#1710767203
ss -tan | head
#1710767212
grep -i error /var/log/syslog | tail -50
#1710767272
find /tmp -maxdepth 1 -type f | head
#1710767504
grep -i warning /var/log/syslog | tail
#1710767571
tail -200 /var/log/syslog
#1710767642
ls -lah /tmp | head
#1710767700
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710768018
cat /etc/crontab
#1710768082
journalctl -u sshd --since '1 hour ago'
#1710768480
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710768546
uname -a
#1710768607
clear
#1710777334
systemctl is-active systemd-resolved
