#1710771225
systemctl is-active sshd
#1710771351
journalctl -u systemd-resolved -n 50 --no-pager
#1710771360
ps aux | grep systemd-resolved
#1710771877
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710772126
tail -20 /var/log/syslog
#1710772133
nmcli device status 2>/dev/null
#1710772294
systemctl status sshd
#1710777988
systemctl is-active gunicorn
#1710778000
journalctl -u systemd-resolved -n 100 --no-pager
#1710778234
ss -ltnp | grep sshd
#1710778441
systemctl cat sshd 2>/dev/null | head -40
#1710778488
last -5
#1710778495
ss -s
#1710779773
df -h /var
#1710779851
du -sh /tmp/*
#1710779926
getent hosts localhost
#1710780872
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
