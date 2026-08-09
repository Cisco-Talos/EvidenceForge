#1710775855
grep -i warning /var/log/syslog | tail
#1710775979
umask
#1710776073
cat /etc/issue
#1710776146
systemctl list-timers
#1710779561
cd -
#1710779573
journalctl --no-pager -n 5
#1710779631
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710779709
htop
#1710780135
grep -i error /var/log/syslog | tail -100
#1710780227
nmcli device status 2>/dev/null
