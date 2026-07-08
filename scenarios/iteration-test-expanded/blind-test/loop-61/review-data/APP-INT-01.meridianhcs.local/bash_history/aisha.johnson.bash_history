#1710765761
df -h /tmp
#1710766145
systemctl status gunicorn
#1710766433
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710766496
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710766582
df -h /
#1710766635
grep -i 'session opened' /var/log/auth.log | tail -10
#1710766690
cat /etc/crontab
#1710770101
systemctl is-active systemd-resolved
#1710770111
journalctl -u gunicorn --since '30 min ago' --no-pager | tail -50
#1710770155
ps aux | grep systemd-resolved
#1710770376
systemctl cat systemd-resolved 2>/dev/null | head -40
#1710770713
netstat -an | grep ESTABLISHED | wc -l
#1710771015
udevadm info --query=property --name=/dev/null | head
