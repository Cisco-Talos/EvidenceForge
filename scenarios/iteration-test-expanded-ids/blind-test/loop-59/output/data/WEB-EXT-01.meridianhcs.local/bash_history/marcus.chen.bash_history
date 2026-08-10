#1710767493
htop
#1710767589
ss -ltnp | grep apache2
#1710767639
grep -i error /var/log/syslog | tail -50
#1710767837
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710768226
nmcli connection show --active
#1710768603
ip -o addr show scope global
#1710768651
timedatectl
#1710768746
udevadm info --query=property --name=/dev/null | head
#1710775046
cat /etc/hostname
#1710775095
getent hosts localhost
#1710775233
getent passwd $(whoami)
#1710775314
ps aux
#1710775368
tail -200 /var/log/syslog
#1710775536
grep -i 'failed password' /var/log/auth.log | wc -l
#1710776040
du -sh /var/log
#1710779843
tail -200 /var/log/auth.log
#1710780236
grep -i 'session opened' /var/log/auth.log | tail -20
#1710780305
ls -ltr /var/log/ | tail -10
#1710780388
systemctl list-timers --all --no-pager | head
#1710781774
ss -ltnp | grep php-fpm
