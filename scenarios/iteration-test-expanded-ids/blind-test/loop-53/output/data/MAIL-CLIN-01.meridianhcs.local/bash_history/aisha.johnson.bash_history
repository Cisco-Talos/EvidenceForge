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
#1710776685
who -a
#1710776789
tail -50 /var/log/auth.log
#1710777154
grep -i 'failed password' /var/log/auth.log | tail -20
#1710782391
ss -tulnp
#1710782775
systemctl status NetworkManager --no-pager
#1710782819
journalctl -u sshd --since '1 hour ago'
