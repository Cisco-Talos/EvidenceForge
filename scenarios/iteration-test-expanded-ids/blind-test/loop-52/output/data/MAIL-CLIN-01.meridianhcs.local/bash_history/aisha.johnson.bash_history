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
#1710775681
systemctl status systemd-resolved --no-pager
#1710775999
journalctl -u postfix --since '30 min ago' --no-pager | tail -200
#1710776222
ss -ltnp | grep postfix
#1710782351
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710782431
grep -i 'session opened' /var/log/auth.log | tail -20
#1710782681
journalctl -u sshd --since '1 hour ago'
#1710782691
last -20
#1710782738
whoami
