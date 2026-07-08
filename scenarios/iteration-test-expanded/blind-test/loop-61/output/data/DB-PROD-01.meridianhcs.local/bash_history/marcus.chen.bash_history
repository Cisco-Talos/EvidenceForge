#1710781552
grep -i failed /var/log/auth.log | tail
#1710781820
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710781980
find /tmp -maxdepth 1 -type f | head
#1710782536
htop
#1710782585
locale
#1710782657
cat /proc/cpuinfo | grep 'model name' | head -1
#1710782706
journalctl --no-pager -n 5
#1710782719
cat /proc/version | cut -d' ' -f1-3
#1710782754
du -sh /tmp/*
#1710782996
cd ~
#1710783223
ss -tan | head
#1710784328
ps aux | grep mysql
#1710784365
systemctl status NetworkManager --no-pager
#1710784419
yum check-update 2>/dev/null
#1710784468
dmesg | tail -30
#1710784557
journalctl -p err --no-pager -n 10
#1710784581
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
#1710784654
dmesg --ctime | tail -20
#1710784780
cat /etc/fstab
