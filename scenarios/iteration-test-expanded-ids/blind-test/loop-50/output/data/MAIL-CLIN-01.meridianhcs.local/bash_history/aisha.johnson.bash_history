#1710763254
systemctl list-units --failed
#1710763320
date -u
#1710763330
ls -lt /var/log | head
#1710763393
df -h /var
#1710763406
ip route
#1710776600
timedatectl
#1710776674
free -h
#1710776907
systemctl --failed --no-pager
#1710779599
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710779633
du -sh /var/log/*
#1710779667
last -20
