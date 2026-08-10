#1710769005
pwd
#1710769117
ls -lh
#1710769191
date
#1710769233
du -sh /var/log/*
#1710769301
ss -tulnp
#1710769613
journalctl -u sshd --since '1 hour ago'
#1710769660
netstat -an | grep ESTABLISHED | wc -l
#1710769695
uname -a
#1710769777
cat /etc/hostname
#1710770230
systemd-analyze blame | head
#1710771289
systemctl status sshd --no-pager
#1710771631
journalctl -u php-fpm -n 200 --no-pager
#1710771721
ss -ltnp | grep php-fpm
#1710771995
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710772007
systemctl restart systemd-resolved
#1710773403
cat /etc/issue
#1710773526
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710773564
df -h /var
#1710773658
journalctl -u apache2 -n 20
#1710773951
ls -la
#1710774009
grep -i error /var/log/syslog | tail -20
#1710781945
udevadm info --query=property --name=/dev/null | head
#1710782006
tail -100 /var/log/syslog
#1710782099
cat /etc/hosts
#1710782111
grep -m1 'model name' /proc/cpuinfo
#1710782391
netstat -an | grep ESTABLISHED | wc -l
#1710782412
journalctl -xe --no-pager | tail -20
#1710782648
uptime
#1710782854
id
#1710782884
top -bn1 | head -20
