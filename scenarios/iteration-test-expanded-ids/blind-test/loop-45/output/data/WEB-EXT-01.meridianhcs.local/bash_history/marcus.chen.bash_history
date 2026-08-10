#1710782933
grep -i 'failed password' /var/log/auth.log | wc -l
#1710782974
cat /etc/hosts
#1710783328
systemctl list-timers
#1710783372
udevadm info --query=property --name=/dev/null | head
#1710783425
ss -ltnp | grep php-fpm
#1710783726
nmcli device status 2>/dev/null
#1710783756
ls -la
#1710783995
dmesg --ctime | tail -20
