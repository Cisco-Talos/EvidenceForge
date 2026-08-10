#1710766330
whoami
#1710766774
ls -lah
#1710766833
history | tail -15
#1710766847
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710773697
cat /etc/crontab
#1710774881
ss -s
#1710774914
systemctl list-timers
#1710774961
fd
#1710774986
iostat -x 1 3
#1710775274
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710775310
cat /proc/meminfo | head -5
#1710775635
free -h
#1710776915
last -20
#1710777380
lsblk
#1710777454
ss -tulnp
#1710777461
pwd
#1710777637
who -a
#1710777669
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710777747
grep -i 'session opened' /var/log/auth.log | tail -20
#1710777824
ls -ld /var/log
#1710777832
cat /proc/meminfo | head -5
#1710778280
last -20
#1710778697
tail -200 /var/log/auth.log
#1710778739
ip route get 8.8.8.8
#1710778811
systemctl list-timers
#1710778905
who
#1710779081
cd /tmp
#1710779125
grep -i warning /var/log/syslog | tail
#1710779154
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710779188
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
