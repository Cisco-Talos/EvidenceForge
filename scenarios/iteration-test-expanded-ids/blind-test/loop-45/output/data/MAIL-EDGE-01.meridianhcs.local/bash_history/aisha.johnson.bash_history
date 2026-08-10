#1710765508
hostname -f
#1710765576
ls -lah
#1710766139
date
#1710766194
ss -s
#1710766773
last -20
#1710766867
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710777450
date -u
#1710777840
cat /proc/meminfo | head -5
#1710779748
mount | column -t
#1710783323
journalctl -xe --no-pager | tail -20
#1710783876
systemctl restart dovecot
#1710784086
journalctl -u smtp --since '30 min ago' --no-pager | tail -20
