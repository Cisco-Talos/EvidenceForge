#1710766546
hostname -f
#1710766748
ls -lah
#1710769418
timedatectl
#1710769477
free -h
#1710769890
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710770272
ss -tan | head
#1710770305
file /usr/bin/ls
#1710770317
last -20
#1710770406
ls
#1710770494
systemctl restart gunicorn
#1710777565
tail -20 /var/log/auth.log
