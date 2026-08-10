#1710764558
who -a
#1710764772
tail -200 /var/log/auth.log
#1710764890
grep -i 'failed password' /var/log/auth.log | tail -20
#1710765288
dmesg | tail -30
#1710765301
du -sh /home/* 2>/dev/null | head
#1710765379
cat /proc/sys/kernel/osrelease
#1710765437
ps -ef | head
#1710765503
ls -ltr /var/log | tail
#1710765810
journalctl -u php-fpm --since '30 min ago' --no-pager | tail -20
#1710765854
tail -20 ~/.bash_history
#1710770961
timedatectl
#1710771183
df -h /
#1710771193
systemctl --failed --no-pager
#1710771249
systemctl list-timers
#1710771294
ps -ef
#1710771414
python3 -V 2>&1
#1710771470
cat /etc/os-release
#1710771575
cat /etc/resolv.conf
#1710771789
ls -lh
#1710772066
ip -br addr
#1710772077
vmstat 1 5
#1710772115
resolvectl query company.okta.com
#1710772202
ls /var/log
#1710772288
hostname
#1710772295
ss -ltnp | grep systemd-resolved
#1710774588
crontab -l
#1710774677
sstat
#1710775845
cat /etc/hostname
#1710775859
ip route
#1710776005
systemctl status NetworkManager --no-pager
#1710776048
cat /proc/cpuinfo | grep 'model name' | head -1
#1710776104
mount | column -t
#1710776332
clear
#1710776387
cat /proc/meminfo | head -5
#1710776400
systemctl restart apache2
#1710776652
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710776673
stat /etc/passwd
