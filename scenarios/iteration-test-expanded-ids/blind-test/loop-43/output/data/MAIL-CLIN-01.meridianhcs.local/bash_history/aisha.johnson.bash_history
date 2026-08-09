#1710769503
systemctl is-active imaps
#1710769690
journalctl -u dovecot --since '30 min ago' --no-pager | tail -200
#1710775211
tail -200 /var/log/auth.log
#1710776192
nmcli connection show --active
#1710779017
cat /proc/meminfo | head -5
