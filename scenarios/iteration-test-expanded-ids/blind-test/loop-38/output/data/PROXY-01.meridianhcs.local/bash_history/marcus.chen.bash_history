#1710772228
systemctl is-active sshd
#1710772403
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710772607
ps aux | grep squid
#1710772815
systemctl cat sshd 2>/dev/null | head -40
#1710772855
cat /proc/version | cut -d' ' -f1-3
#1710773296
loginctl session-status
#1710773323
ss -tulnp
#1710773332
df -h /tmp
#1710773418
ps -ef
#1710773442
ls -ld /var/log
#1710773464
df -h
#1710773533
ls -ltr /var/log | tail
#1710773843
ulimit -n
#1710773887
journalctl -u sshd --since '1 hour ago'
#1710773920
cd /var/log
#1710773981
pwd
#1710773995
free -m
#1710774052
loginctl list-sessions
#1710779138
grep -i failed /var/log/auth.log | tail
#1710780293
apt list --upgradable 2>/dev/null
#1710780345
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710780375
groups
#1710780450
ss -s
#1710780507
ls -lah /tmp | head
#1710780583
grep -i error /var/log/syslog | tail -50
#1710780673
grep -i 'failed password' /var/log/auth.log | wc -l
#1710780762
journalctl -p err --no-pager -n 10
#1710780830
file /usr/bin/ls
#1710781115
command -v python3
#1710781193
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710783110
journalctl --no-pager -n 5
#1710783117
env | sort | head
#1710783155
mount | column -t
#1710783545
cat /proc/meminfo | head -5
#1710783591
ip -o addr show scope global
#1710783599
grep -i warning /var/log/syslog | tail
#1710784770
echo $SHELL
