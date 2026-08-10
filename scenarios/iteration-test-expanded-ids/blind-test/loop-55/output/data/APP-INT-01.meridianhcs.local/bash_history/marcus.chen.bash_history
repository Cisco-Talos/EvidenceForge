#1710766546
hostname -f
#1710766748
ls -lah
#1710771949
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710772342
grep -i 'failed password' /var/log/auth.log | tail -20
#1710772553
grep -i error /var/log/syslog | tail
#1710772592
uname -sr
#1710772752
nmcli connection show --active
#1710772805
tail -f /var/log/syslog &
#1710773103
uptime
#1710773114
ip route
#1710773139
journalctl --since '10 min ago' --no-pager -n 20
#1710773175
getent passwd $(whoami)
#1710774253
cat /etc/passwd | head
#1710774430
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710774503
ls
#1710774572
crontab -l
#1710774911
df -h
#1710774940
journalctl -u sshd --since '1 hour ago'
#1710774954
systemctl list-timers
