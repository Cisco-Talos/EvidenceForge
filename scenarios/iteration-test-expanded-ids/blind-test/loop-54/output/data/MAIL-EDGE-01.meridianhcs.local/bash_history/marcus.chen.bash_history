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
#1710769844
uptime
#1710773566
ps aux --sort=-%mem | head
#1710773588
apt list --upgradable 2>/dev/null
