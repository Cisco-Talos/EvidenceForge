#1710766442
nmcli connection show --active
#1710766451
journalctl --no-pager -n 5
#1710766820
exit
#1710766895
cat /etc/crontab
#1710783129
tail -20 /var/log/auth.log
#1710783585
who
#1710783933
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710783953
du -sh /var/log/*
#1710784004
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710784033
resolvectl status 2>/dev/null | head -30
