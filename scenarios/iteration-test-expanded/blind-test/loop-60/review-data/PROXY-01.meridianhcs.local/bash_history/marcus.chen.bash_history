#1710768051
whoami
#1710768381
ls -lh
#1710768453
date
#1710768502
loginctl session-status
#1710768687
cat /etc/passwd | head
#1710768722
systemd-analyze blame | head
#1710769121
ulimit -n
#1710769934
mount | column -t
#1710770019
resolvectl query login.microsoftonline.com
#1710770213
journalctl -p err --no-pager -n 10
#1710770246
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710770267
cat /etc/issue
#1710782844
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710783246
ss -ltnp | grep sshd
#1710783389
who -a
#1710783751
getent passwd $(whoami)
#1710784014
iostat -x 1 3
#1710784377
ss -ltnp | grep squid
#1710784464
cat /etc/issue
#1710784574
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710784651
tail -f /var/log/syslog &
