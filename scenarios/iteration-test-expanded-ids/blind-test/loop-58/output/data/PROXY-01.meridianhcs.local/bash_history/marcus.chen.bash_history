#1710764222
loginctl session-status
#1710764282
date -u
#1710764364
cat /etc/fstab
#1710764391
ls -ld /var/log
#1710765074
ls /tmp
#1710765080
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710765105
grep -i error /var/log/syslog | tail -100
#1710765439
ss -ltnp | grep sshd
#1710765469
top -bn1 | head -20
#1710765815
stat /etc/passwd
