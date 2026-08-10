#1710770048
systemctl status systemd-resolved --no-pager
#1710770086
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
#1710770095
ps aux | grep gunicorn
#1710770157
systemctl show gunicorn -p ActiveState -p SubState -p MainPID
#1710770218
ls -la
#1710770272
journalctl --no-pager -n 5
#1710770373
ulimit -n
#1710770395
ls
