#1710773714
systemctl is-active gunicorn
#1710773751
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710773833
ps aux | grep gunicorn
#1710777213
vmstat 1 5
#1710777254
tail -20 /var/log/syslog
#1710777263
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710777300
ss -tulnp
#1710777312
free -h
#1710777643
grep -i 'failed password' /var/log/auth.log | wc -l
#1710778058
ls
#1710784520
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
