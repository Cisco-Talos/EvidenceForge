#1710773996
systemctl is-active postfix
#1710784240
systemctl is-active systemd-resolved
#1710784336
journalctl -u systemd-resolved -n 100 --no-pager
#1710784646
ps aux | grep smtp
