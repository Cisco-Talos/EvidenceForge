#1710766330
whoami
#1710766774
ls -lah
#1710766833
history | tail -15
#1710766847
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710769863
netstat -an | grep ESTABLISHED | wc -l
#1710770187
file /usr/bin/ls
#1710770246
systemctl list-units --failed
#1710770372
du -sh /var/log/*
#1710784475
systemctl status imaps --no-pager
#1710784729
journalctl -u postfix --since '30 min ago' --no-pager | tail -20
