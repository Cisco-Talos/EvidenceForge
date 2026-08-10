#1710769192
cat /etc/hosts
#1710769712
exit
#1710769962
ss -ltnp | grep squid
#1710769978
iostat -x 1 3
#1710770210
ls -lh
#1710770243
groups
#1710770267
tail -200 /var/log/auth.log
#1710770300
free -m
#1710770387
umask
#1710770393
cat /etc/fstab
#1710770416
timedatectl
#1710773081
tail -f /var/log/syslog &
#1710773412
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710773494
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710773541
top -bn1 | head -20
#1710773860
ls /tmp
#1710773913
du -sh /var/log
#1710773939
ss -s
#1710784339
systemctl status systemd-resolved --no-pager
#1710784422
journalctl -u systemd-resolved -n 50 --no-pager
#1710784484
ps aux | grep sshd
#1710784555
systemctl show squid -p ActiveState -p SubState -p MainPID
#1710784578
grep -i error /var/log/syslog | tail -100
#1710784607
who
