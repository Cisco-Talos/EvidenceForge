#1710769959
uptime
#1710770268
df -h /
#1710773918
journalctl -u imaps --since '30 min ago' --no-pager | tail -20
#1710777579
who -a
#1710779700
systemctl is-active postfix
#1710780217
journalctl -u smtp -n 200 --no-pager
#1710780341
ss -ltnp | grep smtp
#1710780413
systemctl show imaps -p ActiveState -p SubState -p MainPID
