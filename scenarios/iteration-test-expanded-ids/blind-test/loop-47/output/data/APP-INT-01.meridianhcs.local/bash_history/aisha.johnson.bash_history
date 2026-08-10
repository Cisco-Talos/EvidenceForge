#1710772441
who -a
#1710772927
tail -100 /var/log/auth.log
#1710773017
grep -i 'failed password' /var/log/auth.log | tail -20
#1710773085
grep -i 'session opened' /var/log/auth.log | tail -10
#1710773160
nmcli connection show --active
#1710774974
systemctl is-active systemd-resolved
#1710775051
journalctl -u gunicorn -n 20 --no-pager
#1710775117
ps aux | grep sshd
#1710776555
systemctl cat systemd-resolved 2>/dev/null | head -40
#1710776646
loginctl session-status
#1710776993
systemctl restart gunicorn
