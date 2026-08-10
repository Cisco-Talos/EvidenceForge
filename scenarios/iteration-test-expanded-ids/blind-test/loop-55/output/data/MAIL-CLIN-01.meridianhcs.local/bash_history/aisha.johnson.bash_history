#1710769768
who -a
#1710770193
systemctl is-active dovecot
#1710771248
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710771379
grep -i 'session opened' /var/log/auth.log | tail -20
#1710771487
grep -i error /var/log/syslog | tail -100
#1710771514
ip route
#1710774883
getent passwd $(whoami)
#1710775104
echo $SHELL
#1710775378
cat /etc/hostname
#1710775544
env | sort | head
#1710775568
tail -200 /var/log/auth.log
