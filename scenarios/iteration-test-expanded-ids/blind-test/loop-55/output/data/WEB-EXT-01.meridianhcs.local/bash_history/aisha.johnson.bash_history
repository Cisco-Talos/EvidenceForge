#1710780330
tail -100 /var/log/auth.log
#1710780802
grep -i 'failed password' /var/log/auth.log | tail -20
#1710780887
vmstat 1 5
#1710780943
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710780988
journalctl -xe --no-pager | tail -20
#1710781001
groups
