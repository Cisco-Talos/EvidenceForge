#1710765027
systemctl status imaps --no-pager
#1710765035
journalctl -u imaps --since '30 min ago' --no-pager | tail -50
#1710765390
ss -ltnp | grep postfix
#1710766738
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710767010
ip -o addr show scope global
#1710767018
getent hosts localhost
#1710767315
crontab -l
#1710767324
groups
#1710767735
loginctl list-sessions
#1710776368
nmcli device status 2>/dev/null
#1710776416
journalctl -u imaps --since '30 min ago' --no-pager | tail -20
#1710776638
grep -i warning /var/log/syslog | tail
#1710776926
ss -tan | head
#1710777022
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710777290
systemctl status sshd
#1710777304
ls -ltr /var/log/ | tail -10
#1710777365
df -h
#1710777377
ls
