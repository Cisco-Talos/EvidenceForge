#1710782006
systemctl is-active sshd
#1710782277
journalctl -u sshd -n 100 --no-pager
#1710782351
ss -ltnp | grep gunicorn
#1710782384
systemctl show gunicorn -p ActiveState -p SubState -p MainPID
#1710782517
cat /etc/fstab
#1710782698
ls -ld /var/log
#1710782772
grep -i 'failed password' /var/log/auth.log | wc -l
#1710783634
grep -i error /var/log/syslog | tail -100
#1710783665
free -m
#1710783738
cat /proc/meminfo | head -5
#1710784024
ps aux | grep systemd-resolved
#1710784034
grep -m1 'model name' /proc/cpuinfo
#1710784154
ulimit -n
