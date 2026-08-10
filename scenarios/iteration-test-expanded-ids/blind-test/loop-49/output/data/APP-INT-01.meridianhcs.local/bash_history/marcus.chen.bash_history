#1710773714
systemctl is-active gunicorn
#1710773751
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710773833
ps aux | grep gunicorn
