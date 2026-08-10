#1710763362
hostname -f
#1710769397
pwd
#1710769485
ls -ltr
#1710769890
history | tail -15
#1710769973
cd ~
#1710770044
hostname
#1710770100
ip route
#1710770154
journalctl --since '10 min ago' --no-pager -n 20
#1710770241
cd -
#1710770415
vmstat 1 5
#1710776929
last -20
#1710776938
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710777216
grep -i 'session opened' /var/log/auth.log | tail -20
#1710777266
systemctl restart systemd-resolved
#1710777668
lsblk
#1710777758
grep -m1 'model name' /proc/cpuinfo
#1710779917
systemctl status dovecot --no-pager
#1710779927
journalctl -u smtp -n 50 --no-pager
#1710780024
ps aux | grep systemd-resolved
#1710780315
systemctl cat smtp 2>/dev/null | head -40
#1710780383
loginctl session-status
#1710780412
ss -tan | head
#1710780458
grep -i warning /var/log/syslog | tail
