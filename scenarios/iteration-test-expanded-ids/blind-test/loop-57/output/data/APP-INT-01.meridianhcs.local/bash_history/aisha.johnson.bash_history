#1710777970
systemctl is-active gunicorn
#1710778010
journalctl -u gunicorn --since '30 min ago' --no-pager | tail -100
#1710778055
ss -ltnp | grep gunicorn
#1710781112
systemctl is-active sshd
#1710782428
cat /proc/meminfo | head -5
#1710782704
ss -tan | head
#1710783690
systemctl restart systemd-resolved
