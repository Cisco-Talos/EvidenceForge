#1710763241
yum check-update 2>/dev/null
#1710765382
uptime
#1710766109
ss -s
#1710766221
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710769406
systemctl status sshd --no-pager
#1710769936
journalctl -u mysql -n 200 --no-pager
#1710777987
ls -ltr
#1710778573
history | tail -15
#1710779793
ip -br addr
#1710782542
du -sh /home/* 2>/dev/null | head
#1710782869
mount | column -t
#1710782930
ulimit -n
